"""Measure what each RL hardening action actually does to each attack.

Every attack scenario that runs against the in-process personas is executed once
per hardening action, with that action's effects enforced by the real sensor
code (``common.hardening``) for the attacker's address. The outcome components
the agent is rewarded on (harm, distinct behaviours, engagement) are recorded,
together with the context the agent would see (stage from the detections the
unhardened run produced, and the attack surface).

The resulting table, ``evaluation/hardening/outcomes.json``, is the ground truth
the training simulator samples from (``backend.app.tools.train_hardening``). It
contains no assumed numbers: rerun this script after changing a persona or a
scenario and the simulator changes with it.

    python -m evaluation.measure_hardening [--repeats 2] [--out evaluation/hardening/outcomes.json]

Loopback only: personas bind 127.0.0.1 and the runner is redirected to them.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from attacks.runner.inprocess import InProcessLab  # noqa: E402
from backend.app.services import hardening as rl  # noqa: E402
from backend.app.services.detector import detect  # noqa: E402
from backend.app.services.sessionizer import reconstruct_sessions  # noqa: E402

COWRIE_SERVICES = {"ssh", "telnet", "iot"}
EXTERNAL_ONLY = {"mqtt", "router", "camera"}  # served by legacy containers, not the persona runtime


def runnable(doc: dict) -> bool:
    services = {step["service"] for step in doc["steps"]}
    return doc["trial_kind"] == "attack" and not services & COWRIE_SERVICES and not (services & EXTERNAL_ONLY and not doc.get("models"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--out", default=str(ROOT / "evaluation/hardening/outcomes.json"))
    parser.add_argument("--only", nargs="*", help="scenario ids (default: every runnable attack)")
    args = parser.parse_args()

    docs = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "attacks/scenarios").glob("*.yaml"))]
    docs = [d for d in docs if runnable(d) and (not args.only or d["id"] in args.only)]
    lab = InProcessLab(Path(tempfile.mkdtemp(prefix="trapsig-measure-"))).start()
    rows = []
    try:
        for doc in docs:
            statuses, events = lab.run(doc)
            kinds = sorted({d["type"] for s in reconstruct_sessions(events) for d in detect(s)})
            services = sorted({(e.get("service") or {}).get("name") for e in events if (e.get("service") or {}).get("name")})
            row = {
                "scenario_id": doc["id"],
                "expected_detection": doc["expected_detection"],
                "detections": kinds,
                "stage": rl.stage_for(kinds or [doc["expected_detection"]]),
                "surface": rl.surface_for(services),
                "services": services,
                "actions": {},
            }
            for action in rl.ACTIONS:
                samples = []
                for repeat in range(args.repeats):
                    started = time.monotonic()
                    statuses, events = lab.run(doc, effects=rl.EFFECTS[action], decision_id=f"MEASURE-{action}-{repeat}")
                    samples.append(
                        {
                            "harm_events": sum(rl.is_harm(e) for e in events),
                            "behaviours": len({rl.behaviour_key(e) for e in events}),
                            "events": len(events),
                            "steps_completed": statuses.count("completed"),
                            "steps_failed": statuses.count("failed"),
                            "seconds": round(time.monotonic() - started, 3),
                        }
                    )
                row["actions"][action] = samples
            rows.append(row)
            observe = row["actions"]["observe"][0]
            print(f"{doc['id']:34s} {row['stage']:10s} {row['surface']}  observe harm={observe['harm_events']} behaviours={observe['behaviours']}", flush=True)
    finally:
        lab.stop()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "each runnable attack scenario x each hardening action, real persona runtime on loopback, effects enforced by sensor code",
        "repeats": args.repeats,
        "actions": {a: list(e) for a, e in rl.EFFECTS.items()},
        "scenarios": rows,
    }
    out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"wrote {len(rows)} scenarios x {len(rl.ACTIONS)} actions to {out}")


if __name__ == "__main__":
    main()
