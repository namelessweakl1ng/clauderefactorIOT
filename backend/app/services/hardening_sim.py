"""Offline training and evaluation of the RL hardening agent.

Why a simulator
---------------
A lab sees a few hundred attacker sessions; a bandit over 16 contexts x 5 arms
needs more than that before its live choices are better than a fixed rule. So the
agent is pre-trained offline and then keeps learning online from real outcomes.

What is measured and what is modelled
-------------------------------------
* **Measured** (``evaluation/measure_hardening.py``): for every runnable attack
  scenario and every action, the harm, distinct behaviours and engagement the
  *real persona runtime* produced with that action's effects enforced. The
  simulator samples these; it never invents a per-step outcome.
* **Modelled** (stated here, shown on the dashboard): who the attackers are.
  Three archetypes differ in patience (does friction such as a tarpit make them
  leave early), in how often they come back, and in whether they escalate after
  success (an operator who got in moves to a later kill-chain stage; one who was
  blocked tries a different attack at the same stage). These are assumptions and
  are reported with the results.

Evaluation
----------
Scenarios are split into train and held-out groups, so the evaluation asks
whether the learned policy generalises to *attacks it never trained on*. Every
policy is run on the same episode seeds (common random numbers), so the reward
difference against the expert-rule baseline is paired and gets a 95 % CI. The
promotion gate requires the learned policy to beat the rule baseline with the CI
lower bound above zero, to not raise the harm rate, and to never break the
safety floor.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from . import hardening as rl

ARCHETYPES: dict[str, dict[str, Any]] = {
    # Mirai-style bots: impatient, come back to reinfect, never adapt; some ICS scripts write on first contact.
    "bot": {
        "weight": 0.5,
        "patience": 0.25,
        "return_p": 0.35,
        "escalates": False,
        "start": {"recon": 0.3, "credential": 0.45, "intrusion": 0.15, "ics_impact": 0.1},
    },
    # Internet-wide scanners: moderately patient, mostly reconnaissance, return often.
    "scanner": {"weight": 0.3, "patience": 0.5, "return_p": 0.6, "escalates": False, "start": {"recon": 0.85, "credential": 0.15}},
    # Human operators: patient, persistent, escalate after success and adapt when blocked.
    "operator": {
        "weight": 0.2,
        "patience": 0.9,
        "return_p": 0.75,
        "escalates": True,
        "start": {"recon": 0.5, "credential": 0.25, "intrusion": 0.1, "ics_impact": 0.15},
    },
}
OT_SHARE = 0.4  # fraction of episodes that start on the OT surface (when OT scenarios exist)
# How much each action slows or frustrates an attacker (chance an impatient one leaves mid-way).
FRICTION = {"observe": 0.0, "tarpit": 0.5, "deny_auth": 0.3, "read_only": 0.25, "quarantine": 0.8}
MAX_VISITS = 5
REPEAT_NOVELTY = 0.2  # share of behaviours still new when the same attack is repeated


class Policy(Protocol):
    name: str

    def act(self, context: str, rng: random.Random) -> str: ...

    def learn(self, context: str, action: str, reward: float) -> None: ...


@dataclass
class FixedPolicy:
    action: str
    name: str = ""

    def __post_init__(self) -> None:
        self.name = self.name or f"always {self.action}"

    def act(self, context: str, rng: random.Random) -> str:
        if context.startswith("ics_impact") and "read_only" not in rl.EFFECTS[self.action]:
            return "read_only"  # every baseline obeys the same safety floor
        return self.action

    def learn(self, context: str, action: str, reward: float) -> None:
        return None


@dataclass
class RandomPolicy:
    name: str = "random"

    def act(self, context: str, rng: random.Random) -> str:
        candidates, _ = rl.allowed_for(context, list(rl.ACTIONS))
        return rng.choice(candidates)

    def learn(self, context: str, action: str, reward: float) -> None:
        return None


RULES = {"recon": "observe", "credential": "deny_auth", "intrusion": "read_only", "ics_impact": "read_only"}


@dataclass
class RulePolicy:
    """What an analyst would configure by hand: watch recon, refuse logins, freeze writes."""

    name: str = "expert rules"

    def act(self, context: str, rng: random.Random) -> str:
        return RULES[context.split("|", 1)[0]]

    def learn(self, context: str, action: str, reward: float) -> None:
        return None


@dataclass
class BanditPolicy:
    name: str
    posteriors: dict[str, dict[str, dict[str, float]]] = field(default_factory=rl.empty_posteriors)
    learning: bool = True
    greedy: bool = False
    discount: float = 0.995

    def act(self, context: str, rng: random.Random) -> str:
        if self.greedy:
            candidates, _ = rl.allowed_for(context, list(rl.ACTIONS))
            means = {a: rl.posterior_mean(rl.pooled_arm(self.posteriors, context, a)) for a in candidates}
            return max(candidates, key=lambda a: (means[a], -rl.ACTIONS.index(a)))
        return str(rl.choose(context, self.posteriors, list(rl.ACTIONS), rng)["action"])

    def learn(self, context: str, action: str, reward: float) -> None:
        if self.learning:
            rl.update(self.posteriors, context, action, reward, discount=self.discount)


# --------------------------------------------------------------------------- #
# Outcome table and episodes
# --------------------------------------------------------------------------- #


class OutcomeTable:
    def __init__(self, report: dict[str, Any], scenario_ids: set[str] | None = None) -> None:
        self.rows = [r for r in report["scenarios"] if scenario_ids is None or r["scenario_id"] in scenario_ids]
        if not self.rows:
            raise ValueError("outcome table has no scenarios")
        self.by_stage: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in self.rows:
            self.by_stage.setdefault((row["stage"], row["surface"]), []).append(row)

    def pick(self, stage: str, surface: str, rng: random.Random, exclude: str | None = None) -> dict[str, Any]:
        order = rl.STAGES[rl.STAGES.index(stage) :] + tuple(reversed(rl.STAGES[: rl.STAGES.index(stage)]))
        for candidate_stage in order:  # nearest available stage, preferring later ones
            for candidate_surface in (surface, "ot" if surface == "it" else "it"):
                rows = [r for r in self.by_stage.get((candidate_stage, candidate_surface), []) if r["scenario_id"] != exclude]
                if rows:
                    return rng.choice(rows)
        return rng.choice(self.rows)

    def surfaces(self) -> set[str]:
        return {r["surface"] for r in self.rows}


@dataclass
class Step:
    context: str
    action: str
    reward: float
    harm: bool
    intel: float
    engaged: float
    left_early: bool
    scenario_id: str
    archetype: str


def realise(row: dict[str, Any], action: str, archetype: dict[str, Any], repeated: bool, rng: random.Random) -> dict[str, Any]:
    """One visit's reward components from the measured table plus the attacker model."""
    sample = rng.choice(row["actions"][action])
    behaviours = int(sample["behaviours"])
    harm = int(sample["harm_events"]) > 0
    engaged = 1.0 if sample["events"] else 0.0
    left = rng.random() < FRICTION[action] * (1.0 - archetype["patience"])
    if left and behaviours:
        behaviours = rng.randint(1, max(1, behaviours // 2))  # left part-way: saw only the start of the tooling
    new = behaviours * (REPEAT_NOVELTY if repeated else 1.0)
    intel = min(1.0, new / rl.INTEL_SATURATION)
    reward = rl.REWARD_WEIGHTS["intel"] * intel + rl.REWARD_WEIGHTS["engaged"] * engaged - rl.REWARD_WEIGHTS["harm"] * (1.0 if harm else 0.0)
    return {"reward": max(-1.0, min(1.0, reward)), "harm": harm, "intel": intel, "engaged": engaged, "left": left}


def _weighted(options: dict[str, float], rng: random.Random) -> str:
    roll, total = rng.random() * sum(options.values()), 0.0
    for key, weight in options.items():
        total += weight
        if roll <= total:
            return key
    return next(iter(options))


def episode(table: OutcomeTable, policy: Policy, rng: random.Random) -> list[Step]:
    """One attacker: first visit, then returns (with escalation or adaptation) until they stop."""
    kind = _weighted({k: v["weight"] for k, v in ARCHETYPES.items()}, rng)
    archetype = ARCHETYPES[kind]
    surface = "ot" if "ot" in table.surfaces() and rng.random() < OT_SHARE else "it"
    row = table.pick(_weighted(archetype["start"], rng), surface, rng)
    seen: set[str] = set()
    steps: list[Step] = []
    for visit in range(MAX_VISITS):
        context = rl.context_key(row["stage"], visit > 0, row["surface"])
        action = policy.act(context, rng)
        outcome = realise(row, action, archetype, row["scenario_id"] in seen, rng)
        policy.learn(context, action, outcome["reward"])
        steps.append(Step(context, action, outcome["reward"], outcome["harm"], outcome["intel"], outcome["engaged"], outcome["left"], row["scenario_id"], kind))
        seen.add(row["scenario_id"])
        return_p = archetype["return_p"] * (0.6 if outcome["left"] else 1.0)
        if rng.random() >= return_p:
            break
        stage_index = rl.STAGES.index(row["stage"])
        if outcome["harm"] and archetype["escalates"] and stage_index + 1 < len(rl.STAGES):
            row = table.pick(rl.STAGES[stage_index + 1], row["surface"], rng)  # got in: go further
        elif not outcome["harm"] and archetype["escalates"]:
            row = table.pick(row["stage"], row["surface"], rng, exclude=row["scenario_id"])  # blocked: try another way
        # bots and scanners simply repeat what they did
    return steps


def run_policy(table: OutcomeTable, policy: Policy, episodes: int, seed: int) -> list[list[Step]]:
    out = []
    for index in range(episodes):
        out.append(episode(table, policy, random.Random(seed * 1_000_003 + index)))
    return out


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


def expected_rewards(table: OutcomeTable, samples: int = 400, seed: int = 7) -> dict[str, dict[str, float]]:
    """Monte-Carlo E[reward | context, action] under the attacker mix (for regret)."""
    rng = random.Random(seed)
    totals: dict[str, dict[str, list[float]]] = {}
    for row in table.rows:
        for returning in (False, True):
            context = rl.context_key(row["stage"], returning, row["surface"])
            for action in rl.ACTIONS:
                bucket = totals.setdefault(context, {}).setdefault(action, [])
                for _ in range(max(1, samples // max(1, len(table.rows)))):
                    kind = _weighted({k: v["weight"] for k, v in ARCHETYPES.items()}, rng)
                    bucket.append(realise(row, action, ARCHETYPES[kind], returning and rng.random() < 0.5, rng)["reward"])
    return {c: {a: sum(v) / len(v) for a, v in arms.items()} for c, arms in totals.items()}


def summarise(name: str, runs: list[list[Step]], expected: dict[str, dict[str, float]]) -> dict[str, Any]:
    steps = [s for run in runs for s in run]
    rewards = [s.reward for s in steps]
    n = len(rewards)
    mean = sum(rewards) / n
    sd = math.sqrt(sum((r - mean) ** 2 for r in rewards) / max(1, n - 1))
    regret = []
    for s in steps:
        if s.context in expected:
            allowed, _ = rl.allowed_for(s.context, list(rl.ACTIONS))
            regret.append(max(expected[s.context][a] for a in allowed) - expected[s.context][s.action])
    floor_breaches = sum(1 for s in steps if s.context.startswith("ics_impact") and "read_only" not in rl.EFFECTS[s.action])
    actions = {a: round(sum(s.action == a for s in steps) / n, 4) for a in rl.ACTIONS}
    return {
        "policy": name,
        "decisions": n,
        "episodes": len(runs),
        "mean_reward": round(mean, 4),
        "mean_reward_ci95": [round(mean - 1.96 * sd / math.sqrt(n), 4), round(mean + 1.96 * sd / math.sqrt(n), 4)],
        "harm_rate": round(sum(s.harm for s in steps) / n, 4),
        "mean_intel": round(sum(s.intel for s in steps) / n, 4),
        "engagement": round(sum(s.engaged for s in steps) / n, 4),
        "left_early_rate": round(sum(s.left_early for s in steps) / n, 4),
        "mean_regret": round(sum(regret) / len(regret), 4) if regret else None,
        "safety_floor_breaches": floor_breaches,
        "action_mix": actions,
    }


def paired_difference(a: list[list[Step]], b: list[list[Step]]) -> dict[str, Any]:
    """Per-episode mean reward of a minus b on common seeds, with a 95 % CI."""
    diffs = [sum(s.reward for s in x) / len(x) - sum(s.reward for s in y) / len(y) for x, y in zip(a, b, strict=True)]
    n = len(diffs)
    mean = sum(diffs) / n
    sd = math.sqrt(sum((d - mean) ** 2 for d in diffs) / max(1, n - 1))
    return {"mean": round(mean, 4), "ci95": [round(mean - 1.96 * sd / math.sqrt(n), 4), round(mean + 1.96 * sd / math.sqrt(n), 4)], "episodes": n}


def split_scenarios(report: dict[str, Any], holdout: float, seed: int) -> tuple[set[str], set[str]]:
    """Hold out a share of scenarios per (stage, surface) group, keeping at least one per group for training."""
    rng = random.Random(seed)
    groups: dict[tuple[str, str], list[str]] = {}
    for row in report["scenarios"]:
        groups.setdefault((row["stage"], row["surface"]), []).append(row["scenario_id"])
    train: set[str] = set()
    test: set[str] = set()
    for ids in groups.values():
        ids = sorted(ids)
        rng.shuffle(ids)
        k = int(round(len(ids) * holdout)) if len(ids) > 1 else 0
        k = min(k, len(ids) - 1)
        test.update(ids[:k])
        train.update(ids[k:])
    return train, test


def learning_curve(runs: list[list[Step]], bucket: int) -> list[dict[str, float]]:
    steps = [s for run in runs for s in run]
    out = []
    for start in range(0, len(steps), bucket):
        chunk = steps[start : start + bucket]
        out.append(
            {
                "decisions": start + len(chunk),
                "mean_reward": round(sum(s.reward for s in chunk) / len(chunk), 4),
                "harm_rate": round(sum(s.harm for s in chunk) / len(chunk), 4),
            }
        )
    return out


def train_and_evaluate(
    report: dict[str, Any],
    *,
    train_episodes: int = 20000,
    eval_episodes: int = 1500,
    holdout: float = 0.3,
    seed: int = 20261127,
    policy_factory: Callable[[], BanditPolicy] | None = None,
) -> dict[str, Any]:
    train_ids, test_ids = split_scenarios(report, holdout, seed)
    train_table = OutcomeTable(report, train_ids)
    test_table = OutcomeTable(report, test_ids) if test_ids else train_table
    # The simulator is stationary, so offline training keeps all evidence (discount 1);
    # discounting is for the live agent, where attacker populations drift.
    learner = policy_factory() if policy_factory else BanditPolicy("thompson (training)", discount=1.0)
    training_runs = run_policy(train_table, learner, train_episodes, seed)
    trained = learner.posteriors

    expected = expected_rewards(test_table, seed=seed + 1)
    contenders: list[Policy] = [
        BanditPolicy("learned (greedy)", posteriors=_copy(trained), learning=False, greedy=True),
        BanditPolicy("learned (thompson, keeps learning)", posteriors=_copy(trained)),
        BanditPolicy("untrained thompson", posteriors=rl.empty_posteriors()),
        RulePolicy(),
        FixedPolicy("observe"),
        FixedPolicy("quarantine"),
        RandomPolicy(),
    ]
    runs = {p.name: run_policy(test_table, p, eval_episodes, seed + 2) for p in contenders}
    results = [summarise(name, r, expected) for name, r in runs.items()]
    learned, rules = results[0], next(r for r in results if r["policy"] == "expert rules")
    diff = paired_difference(runs["learned (greedy)"], runs["expert rules"])
    checks = {
        "beats expert rules (paired 95% CI lower bound > 0)": diff["ci95"][0] > 0,
        "harm rate not above expert rules": learned["harm_rate"] <= rules["harm_rate"] + 1e-9,
        "no safety-floor breach": learned["safety_floor_breaches"] == 0,
    }
    best = {}
    for context in rl.CONTEXTS:
        allowed, _ = rl.allowed_for(context, list(rl.ACTIONS))
        means = {a: rl.posterior_mean(rl.pooled_arm(trained, context, a)) for a in allowed}
        n = sum(int(trained[context][a]["n"]) for a in rl.ACTIONS)
        best[context] = {
            "action": max(allowed, key=lambda a: (means[a], -rl.ACTIONS.index(a))),
            "expected_reward": round(2 * max(means.values()) - 1, 4),
            "training_outcomes": n,
        }
    return {
        "agent_version": rl.AGENT_VERSION,
        "seed": seed,
        "outcome_table": {"generated_at": report.get("generated_at"), "scenarios": len(report["scenarios"]), "repeats": report.get("repeats")},
        "split": {"train": sorted(train_ids), "held_out": sorted(test_ids)},
        "attacker_model": {"archetypes": ARCHETYPES, "friction": FRICTION, "ot_share": OT_SHARE, "max_visits": MAX_VISITS, "repeat_novelty": REPEAT_NOVELTY},
        "training": {"episodes": train_episodes, "decisions": sum(len(r) for r in training_runs), "curve": learning_curve(training_runs, 500)},
        "evaluation": {"episodes": eval_episodes, "on": "held-out scenarios" if test_ids else "training scenarios", "policies": results},
        "learned_vs_rules": diff,
        "gate": {"checks": checks, "passed": all(checks.values())},
        "best_action_by_context": best,
        "posteriors": trained,
    }


def _copy(posteriors: dict[str, dict[str, dict[str, float]]]) -> dict[str, dict[str, dict[str, float]]]:
    return {c: {a: dict(arm) for a, arm in arms.items()} for c, arms in posteriors.items()}
