"""Did RL hardening change what attackers achieved? Per-arm outcome report.

    python -m evaluation.arm_outcomes --api-url http://127.0.0.1:8000 \\
        --arm baseline=LOCAL-OTIT-BASELINE-3 --arm rl-hardening=LOCAL-OTIT-RL-3 [--out report.json]

`/experiment-lab/compare` answers the detection question (recall, FPR). This
answers the defence question. Every completed attack run's own events, from its
hash-verified dataset bundle, are scored with the agent's own harm definition
(`hardening.is_harm`). The report gives, per arm:

* attacker success: runs where the attacker achieved anything (login, shell
  command, accepted process write, Redis write...), with a Wilson 95% CI;
* hardened runs: runs whose events carry a hardening decision id (the agent acted);
* detection outcomes (TP/FN/TN/FP/INCONCLUSIVE).

It also gives a Fisher exact test on attacker success between the first two arms.
Controls are reported separately and never count as attacker success.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from backend.app.services import hardening as rl
from backend.app.services.experiment_lab import fisher_exact, wilson_interval

from .http import request_json

RESULTS = Path(__file__).parent / "results"


def score_run(record: dict, events: list[dict]) -> dict:
    harm = [e for e in events if rl.is_harm(e)]
    decisions = sorted({(e.get("hardening") or {}).get("decision_id") for e in events if (e.get("hardening") or {}).get("decision_id")})
    effects = sorted({a for e in events for a in (e.get("hardening") or {}).get("actions") or []})
    return {
        "experiment_id": record["experiment_id"],
        "scenario_id": record.get("scenario_id"),
        "trial_kind": record.get("trial_kind"),
        "result": record.get("result"),
        "events": len(events),
        "harm_events": len(harm),
        "attacker_succeeded": bool(harm) and record.get("trial_kind") == "attack",
        "hardened": bool(decisions),
        "effects": effects,
    }


def summarise(runs: list[dict]) -> dict:
    # Score every attack run that produced telemetry, whatever its detection result:
    # a hardened decoy that makes the attack fail (runner reports RUNNER_FAILED, so
    # the detection result is INCONCLUSIVE) is precisely the outcome being measured.
    # Only runs without events (e.g. SETTLE_TIMEOUT) are unscorable.
    attacks = [r for r in runs if r["trial_kind"] == "attack" and r["events"] > 0]
    succeeded = sum(r["attacker_succeeded"] for r in attacks)
    ci = wilson_interval(succeeded, len(attacks)) if attacks else None
    per_scenario: dict[str, dict] = {}
    for r in attacks:
        item = per_scenario.setdefault(r["scenario_id"], {"runs": 0, "attacker_succeeded": 0, "hardened": 0})
        item["runs"] += 1
        item["attacker_succeeded"] += r["attacker_succeeded"]
        item["hardened"] += r["hardened"]
    return {
        "runs": len(runs),
        "attack_runs_scored": len(attacks),
        "attacker_success": succeeded,
        "attacker_success_rate": round(succeeded / len(attacks), 4) if attacks else None,
        "attacker_success_ci95": [round(x, 4) for x in ci] if ci else None,
        "hardened_attack_runs": sum(r["hardened"] for r in attacks),
        "effects_seen": sorted({e for r in runs for e in r["effects"]}),
        "detection_results": dict(Counter(r["result"] or "NONE" for r in runs)),
        "controls_with_harm": sum(1 for r in runs if r["trial_kind"] == "control" and r["harm_events"]),
        "per_scenario": dict(sorted(per_scenario.items())),
    }


def load_arm(api_url: str, batch: str) -> list[dict]:
    runs = []
    for path in sorted((RESULTS / batch).glob("EXP-*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("status") != "completed":
            continue
        bundle = request_json(f"{api_url.rstrip('/')}/experiments/{record['experiment_id']}/dataset")
        runs.append(score_run(record, bundle.get("events") or []))
    return runs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--arm", action="append", required=True, help="label=batch_id[,batch_id...] (repeatable)")
    parser.add_argument("--out")
    args = parser.parse_args()
    arms = {}
    for spec in args.arm:
        label, _, batches = spec.partition("=")
        arms[label] = summarise([run for batch in batches.split(",") for run in load_arm(args.api_url, batch)])
    report: dict = {"arms": arms}
    labels = list(arms)
    if len(labels) >= 2:
        a, b = arms[labels[0]], arms[labels[1]]
        report["attacker_success_fisher_p"] = fisher_exact(
            a["attacker_success"], a["attack_runs_scored"] - a["attacker_success"], b["attacker_success"], b["attack_runs_scored"] - b["attacker_success"]
        )
    text = json.dumps(report, indent=1)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
