"""Grouped cross-validation comparison of rules / ML / anomaly / hybrid detection.

    python -m backend.app.tools.compare_detectors --source synthetic --output report.json
    python -m backend.app.tools.compare_detectors --source logged --store

``synthetic`` needs no infrastructure (CI, laptops) and is labelled as synthetic
in the report; ``logged`` uses completed, conclusive experiments from
Elasticsearch, grouped by experiment so no run straddles train and test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from ..services.detection.comparison import COMPARISON_INDEX, compare, synthetic_corpus


def _table(report: dict) -> str:
    rows = ["engine         macro-F1  alert-F1  alert-FPR  p95 ms"]
    for name, data in report["engines"].items():
        alert = data["alert"]

        def fmt(value, digits=3):
            return "   n/a " if value is None else f"{value:.{digits}f}"

        rows.append(f"{name:<14} {fmt(data['macro_f1'])}    {fmt(alert['f1'])}     {fmt(alert['fpr'])}    {fmt(data['latency_ms']['p95'], 3)}")
    leak = report["leakage_check"]["naive_split"] or {}
    if leak.get("leakage_inflation") is not None:
        rows.append(f"naive random split would overstate ml_trained macro-F1 by {leak['leakage_inflation']:+.3f}")
    if report["synthetic_warning"]:
        rows.append("WARNING: synthetic data - not a measured lab result.")
    return "\n".join(rows)


async def _logged():
    from ..api.detection import logged_samples
    from ..elastic import store

    try:
        return await logged_samples()
    finally:
        await store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("synthetic", "logged"), default="synthetic")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261126)
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--store", action="store_true", help="also write the report to trapsig-comparisons")
    args = parser.parse_args()
    samples = synthetic_corpus(seed=args.seed % 10_000) if args.source == "synthetic" else asyncio.run(_logged())
    report = compare(samples, folds=args.folds, seed=args.seed, epochs=args.epochs)
    print(_table(report))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, default=str))
        print(f"wrote {args.output}")
    if args.store:
        from ..elastic import store

        async def save() -> None:
            try:
                await store.save(COMPARISON_INDEX, report["report_id"], report)
            finally:
                await store.close()

        asyncio.run(save())
        print(f"stored {report['report_id']}")


if __name__ == "__main__":
    main()
