"""Train the RL hardening agent offline, evaluate it, and install it if it passes.

    python -m backend.app.tools.train_hardening                 # train + report (file only)
    python -m backend.app.tools.train_hardening --apply         # also install the prior + store the report in ES

Input: ``evaluation/hardening/outcomes.json`` from ``evaluation/measure_hardening.py``
(the measured effect of every hardening action on every runnable attack).

The report (``evaluation/hardening/training-report.json`` and, with ``--apply``,
index ``trapsig-hardening-training``) compares the learned policy with fixed
baselines on held-out attacks. ``--apply`` installs the learned posteriors as the
live agent's prior only when the gate passes (``--force`` overrides). The prior is
capped at ``PRIOR_CAP`` pseudo-outcomes per arm and any evidence the live agent
has already gathered is kept on top of it, so real outcomes keep moving it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..services import hardening as rl
from ..services.hardening_sim import train_and_evaluate

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTCOMES = ROOT / "evaluation/hardening/outcomes.json"
DEFAULT_REPORT = ROOT / "evaluation/hardening/training-report.json"
TRAINING_INDEX = "trapsig-hardening-training"


def merge_live(prior: dict[str, dict[str, dict[str, float]]], live: dict[str, dict[str, dict[str, float]]]) -> dict[str, dict[str, dict[str, float]]]:
    """Capped trained prior + whatever the live agent has learned since."""
    merged = rl.cap_prior(prior)
    for context, arms in live.items():
        for action, arm in arms.items():
            if context in merged and int(arm.get("n", 0)) > 0:
                target = merged[context][action]
                # Live evidence only: strip any previously installed prior from the arm.
                target["alpha"] += max(0.0, arm["alpha"] - float(arm.get("prior_alpha", 1.0)))
                target["beta"] += max(0.0, arm["beta"] - float(arm.get("prior_beta", 1.0)))
                target["n"], target["reward_sum"] = int(arm["n"]), float(arm["reward_sum"])
    for arms in merged.values():
        for arm in arms.values():
            arm["alpha"], arm["beta"] = max(1.0, arm["alpha"]), max(1.0, arm["beta"])
    return merged


def headline(report: dict[str, Any]) -> str:
    lines = [f"held-out evaluation ({report['evaluation']['on']}, {report['evaluation']['episodes']} episodes per policy):"]
    lines.append(f"  {'policy':38s} {'reward':>7s} {'95% CI':>17s} {'harm':>6s} {'intel':>6s} {'regret':>7s}")
    for r in report["evaluation"]["policies"]:
        ci = f"[{r['mean_reward_ci95'][0]:+.3f},{r['mean_reward_ci95'][1]:+.3f}]"
        lines.append(f"  {r['policy']:38s} {r['mean_reward']:+7.3f} {ci:>17s} {r['harm_rate']:6.1%} {r['mean_intel']:6.2f} {r['mean_regret'] or 0:7.3f}")
    d = report["learned_vs_rules"]
    lines.append(f"learned - expert rules: {d['mean']:+.4f} per decision, paired 95% CI [{d['ci95'][0]:+.4f}, {d['ci95'][1]:+.4f}]")
    for check, ok in report["gate"]["checks"].items():
        lines.append(f"  [{'PASS' if ok else 'FAIL'}] {check}")
    lines.append("gate: " + ("PASSED" if report["gate"]["passed"] else "FAILED"))
    return "\n".join(lines)


async def install(report: dict[str, Any], *, force: bool) -> str:
    from ..elastic import store

    try:
        await store.save(TRAINING_INDEX, report["report_id"], {k: v for k, v in report.items() if k != "posteriors"})
        if not (report["gate"]["passed"] or force):
            return "report stored; prior NOT installed (gate failed; --force overrides)"
        agent = rl.HardeningAgent(store)
        live = await agent.load_posteriors()
        posteriors = merge_live(report["posteriors"], live)
        await store.save(
            rl.AGENT_INDEX,
            rl.AGENT_DOC_ID,
            {
                "posteriors": posteriors,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "config": rl.config(),
                "agent_version": rl.AGENT_VERSION,
                "trained": {
                    "report_id": report["report_id"],
                    "installed_at": datetime.now(timezone.utc).isoformat(),
                    "gate_passed": report["gate"]["passed"],
                    "forced": force and not report["gate"]["passed"],
                    "prior_cap": rl.PRIOR_CAP,
                },
            },
        )
        return f"report stored and prior installed into {rl.AGENT_INDEX}/{rl.AGENT_DOC_ID}"
    finally:
        await store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outcomes", default=str(DEFAULT_OUTCOMES))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--train-episodes", type=int, default=20000)
    parser.add_argument("--eval-episodes", type=int, default=1500)
    parser.add_argument("--holdout", type=float, default=0.3, help="share of scenarios per (stage, surface) held out for evaluation")
    parser.add_argument("--seed", type=int, default=20261127)
    parser.add_argument("--apply", action="store_true", help="store the report in Elasticsearch and install the prior if the gate passes")
    parser.add_argument("--force", action="store_true", help="with --apply, install even if the gate fails")
    args = parser.parse_args()

    outcomes = json.loads(Path(args.outcomes).read_text(encoding="utf-8"))
    report = train_and_evaluate(outcomes, train_episodes=args.train_episodes, eval_episodes=args.eval_episodes, holdout=args.holdout, seed=args.seed)
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["report_id"] = "HTR-" + sha256(f"{report['generated_at']}|{args.seed}".encode()).hexdigest()[:12]
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(headline(report))
    print(f"report: {args.report}")
    if args.apply:
        print(asyncio.run(install(report, force=args.force)))


if __name__ == "__main__":
    main()
