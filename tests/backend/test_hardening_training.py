"""Hardening agent v2 mechanics (pooling, discounting, poisoning cap, surface,
migration) and the offline trainer/simulator."""

import asyncio
import random

import pytest

from backend.app.services import hardening as rl
from backend.app.services import hardening_sim as sim
from backend.app.tools.train_hardening import merge_live


def test_sixteen_contexts_cover_stage_surface_history():
    assert len(rl.CONTEXTS) == 16 and "ics_impact|ot|returning" in rl.CONTEXTS
    assert rl.surface_for(["web", "s7"]) == "ot" and rl.surface_for(["web", "redis"]) == "it" and rl.surface_for([]) == "it"


def test_sparse_context_borrows_capped_evidence_from_its_stage():
    posteriors = rl.empty_posteriors()
    for _ in range(40):  # lots of evidence in a sibling: read_only is good in ics_impact on OT for new sources
        rl.update(posteriors, "ics_impact|ot|new", "read_only", 0.9)
    pooled = rl.pooled_arm(posteriors, "ics_impact|ot|returning", "read_only")
    assert pooled["borrowed"] == pytest.approx(rl.POOL_CAP)  # capped, not all 40
    assert rl.posterior_mean(pooled) > 0.8 and pooled["n"] == 0
    assert rl.pooled_arm(posteriors, "recon|ot|returning", "read_only")["borrowed"] == 0  # other stages do not leak
    own = rl.pooled_arm(posteriors, "ics_impact|ot|new", "read_only")
    assert own["alpha"] - posteriors["ics_impact|ot|new"]["read_only"]["alpha"] == pytest.approx(0)  # nothing to borrow from itself


def test_discount_lets_the_agent_track_a_changed_attacker_population():
    fast, frozen = rl.empty_posteriors(), rl.empty_posteriors()
    for posteriors, discount in ((fast, 0.95), (frozen, 1.0)):
        for _ in range(200):
            rl.update(posteriors, "credential|it|new", "deny_auth", 0.8, discount=discount)
        for _ in range(40):  # attackers changed: deny_auth now makes them leave with nothing
            rl.update(posteriors, "credential|it|new", "deny_auth", -0.2, discount=discount)
    assert rl.posterior_mean(fast["credential|it|new"]["deny_auth"]) < 0.5 < rl.posterior_mean(frozen["credential|it|new"]["deny_auth"])


def test_single_source_cannot_dominate_learning():
    assert [rl.influence_weight(k, 3) for k in range(3)] == [1.0, 1.0, 1.0]
    assert rl.influence_weight(9, 3) == pytest.approx(0.3)
    poisoned = rl.empty_posteriors()
    for k in range(50):  # one attacker feeds 50 fake "observe is great" outcomes
        rl.update(poisoned, "credential|it|new", "observe", 1.0, weight=rl.influence_weight(k, 3))
    evidence = poisoned["credential|it|new"]["observe"]["alpha"] + poisoned["credential|it|new"]["observe"]["beta"] - 2
    assert evidence < 15  # instead of 50


def test_new_protocol_harm_and_behaviours():
    def ev(ns, details, outcome="success", category="network"):
        return {"event": {"category": category, "action": "x", "outcome": outcome}, "service": {"name": ns}, ns: details}

    assert rl.is_harm(ev("s7", {"write": True, "function": "plc_stop"}))
    assert not rl.is_harm(ev("s7", {"write": True}, "failure"))
    assert rl.is_harm(ev("redis", {"exploit": True, "command": "CONFIG"}))
    assert not rl.is_harm(ev("redis", {"exploit": True}, "failure"))
    assert not rl.is_harm(ev("tftp", {"opcode": "WRQ"}, "failure"))
    assert rl.behaviour_key(ev("bacnet", {"property": "object_name", "service": "read-property"}))[2] == "object_name"
    assert rl.behaviour_key(ev("snmp", {"community": "public"}))[2] == "public"


def test_v1_agent_documents_migrate_to_both_surfaces():
    class Store:
        async def get(self, index, doc_id):
            return {"posteriors": {"credential|new": {"deny_auth": {"alpha": 9.0, "beta": 2.0, "n": 9, "reward_sum": 6.0}}}}

    posteriors = asyncio.run(rl.HardeningAgent(Store()).load_posteriors())
    assert posteriors["credential|it|new"]["deny_auth"]["alpha"] == 9.0 == posteriors["credential|ot|new"]["deny_auth"]["alpha"]


def test_installed_prior_is_capped_and_live_evidence_is_kept():
    trained = rl.empty_posteriors()
    trained["recon|it|new"]["observe"].update(alpha=301.0, beta=101.0, n=400)
    prior = rl.cap_prior(trained)
    arm = prior["recon|it|new"]["observe"]
    assert arm["alpha"] + arm["beta"] - 2 == pytest.approx(rl.PRIOR_CAP) and rl.posterior_mean(arm) == pytest.approx(
        16 / 22
    )  # 3:1 evidence kept, on the Beta(1,1) base
    live = rl.cap_prior(trained)
    live["recon|it|new"]["observe"].update(alpha=live["recon|it|new"]["observe"]["alpha"] + 4, n=4, reward_sum=3.5)  # 4 live outcomes on top
    merged = merge_live(trained, live)["recon|it|new"]["observe"]
    assert merged["alpha"] == pytest.approx(arm["alpha"] + 4) and merged["n"] == 4  # old prior not double-counted


# ---- simulator ----------------------------------------------------------------------- #


def synthetic_report():
    """Two contexts with a known best action each, mimicking measure_hardening output."""

    def row(sid, stage, surface, outcomes):
        return {
            "scenario_id": sid,
            "stage": stage,
            "surface": surface,
            "actions": {
                a: [{"harm_events": h, "behaviours": b, "events": e, "steps_completed": 1, "steps_failed": 0, "seconds": 0.1}]
                for a, (h, b, e) in outcomes.items()
            },
        }

    # credential: observe lets them in; deny_auth keeps them guessing; quarantine ends it.
    cred = {"observe": (1, 6, 8), "tarpit": (1, 5, 8), "deny_auth": (0, 6, 8), "read_only": (1, 6, 8), "quarantine": (0, 1, 2)}
    # ics: writes succeed unless read_only/quarantine; read_only keeps them engaged.
    ics = {"observe": (2, 4, 6), "tarpit": (2, 4, 6), "deny_auth": (2, 4, 6), "read_only": (0, 4, 6), "quarantine": (0, 1, 2)}
    recon = {a: (0, 5 if a in ("observe", "read_only", "deny_auth") else 2, 5) for a in rl.ACTIONS}
    rows = [row(f"cred-{i}", "credential", "it", cred) for i in range(3)] + [row(f"ics-{i}", "ics_impact", "ot", ics) for i in range(3)]
    rows += [row(f"recon-{i}", "recon", s, recon) for i, s in enumerate(["it", "ot", "it"])]
    return {"generated_at": "2026-11-27T00:00:00+00:00", "repeats": 1, "scenarios": rows}


def test_split_holds_out_per_group_and_keeps_training_coverage():
    train, test = sim.split_scenarios(synthetic_report(), 0.34, seed=1)
    assert train.isdisjoint(test) and len(train) + len(test) == 9
    assert {s.split("-")[0] for s in train} == {"cred", "ics", "recon"}  # every group still trains


def test_training_learns_the_known_best_actions_and_passes_the_gate():
    report = sim.train_and_evaluate(synthetic_report(), train_episodes=1500, eval_episodes=600, holdout=0.34, seed=3)
    best = {c: v["action"] for c, v in report["best_action_by_context"].items()}
    assert best["credential|it|new"] == "deny_auth"
    assert best["ics_impact|ot|new"] == "read_only"
    policies = {p["policy"]: p for p in report["evaluation"]["policies"]}
    assert policies["learned (greedy)"]["mean_reward"] > policies["always observe"]["mean_reward"]
    assert policies["learned (greedy)"]["mean_regret"] <= policies["random"]["mean_regret"]
    assert all(p["safety_floor_breaches"] == 0 for p in policies.values())
    assert set(report["gate"]["checks"]) and "posteriors" in report


def test_episodes_are_reproducible_and_escalate_after_success():
    table = sim.OutcomeTable(synthetic_report())
    first = sim.run_policy(table, sim.FixedPolicy("observe"), 50, seed=9)
    again = sim.run_policy(table, sim.FixedPolicy("observe"), 50, seed=9)
    assert [[s.action for s in e] for e in first] == [[s.action for s in e] for e in again]
    stages = [[s.context.split("|")[0] for s in e] for e in sim.run_policy(table, sim.FixedPolicy("observe"), 400, seed=2)]
    assert any(rl.STAGES.index(e[-1]) > rl.STAGES.index(e[0]) for e in stages if len(e) > 1)  # operators move on after getting in


def test_realise_uses_only_measured_outcomes():
    row = synthetic_report()["scenarios"][0]
    rng = random.Random(0)
    harms = {sim.realise(row, "deny_auth", sim.ARCHETYPES["bot"], False, rng)["harm"] for _ in range(50)}
    assert harms == {False}  # deny_auth was measured harmless; the model cannot make it harmful
