"""Offline policy evaluation + baseline comparison (learned vs bootstrap vs rules).

Builds a labeled set from completed experiments (re-derived from raw events, same
as training), or falls back to the deterministic bootstrap set when no logged
data exists, then reports per-head and macro precision/recall/F1 and calibration
for: the active learned policy, the deterministic bootstrap policy, and the frozen
pre-rework rule baseline. This is the research comparison that justifies the
learned-policy rework.

    python -m backend.app.tools.evaluate_detector
    python -m backend.app.tools.evaluate_detector --json
"""

import argparse
import asyncio
import json
from typing import Any

from ..config import get_settings
from ..elastic import store as default_store
from ..services.ml.bootstrap import bootstrap_policy, build_training_examples
from ..services.ml.evaluation import evaluate_policy, evaluate_rule_baseline
from ..services.ml.store import load_latest_policy
from .train_policy import collect_batch


async def evaluate_all(store: Any) -> dict[str, Any]:
    settings = get_settings()
    batch, experiment_count = await collect_batch(store, settings.session_timeout_seconds)
    using_bootstrap = not batch
    examples = batch or build_training_examples()

    active = await load_latest_policy(store) or bootstrap_policy()
    return {
        "dataset": "bootstrap-synthetic" if using_bootstrap else "logged-experiments",
        "experiments_used": experiment_count,
        "example_count": len(examples),
        "active_policy": evaluate_policy(active, examples),
        "bootstrap_policy": evaluate_policy(bootstrap_policy(), examples),
        "rule_baseline": evaluate_rule_baseline(examples),
    }


def _format(report: dict[str, Any]) -> str:
    lines = [
        f"dataset: {report['dataset']}  (examples={report['example_count']}, experiments={report['experiments_used']})",
        "",
        f"{'predictor':<18}{'macro_f1':>10}{'macro_prec':>12}{'macro_rec':>11}{'brier':>9}{'ece':>8}",
    ]
    for key, label in (("active_policy", "learned (active)"), ("bootstrap_policy", "bootstrap"), ("rule_baseline", "rule baseline")):
        row = report[key]

        def fmt(value: float | None) -> str:
            return f"{value:.3f}" if isinstance(value, (int, float)) else "  -  "

        lines.append(
            f"{label:<18}{fmt(row.get('macro_f1')):>10}{fmt(row.get('macro_precision')):>12}"
            f"{fmt(row.get('macro_recall')):>11}{fmt(row.get('brier')):>9}{fmt(row.get('ece')):>8}"
        )
    return "\n".join(lines)


async def _main(as_json: bool) -> None:
    try:
        report = await evaluate_all(default_store)
    finally:
        await default_store.close()
    print(json.dumps(report, indent=2) if as_json else _format(report))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the full metrics report as JSON")
    args = parser.parse_args()
    asyncio.run(_main(args.json))


if __name__ == "__main__":
    main()
