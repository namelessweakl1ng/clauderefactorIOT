"""Offline/batch policy retraining CLI (the adaptation trigger).

Pulls completed experiments from ``trapsig-experiments``, re-derives their linked
sessions from raw ``trapsig-events-*`` (same shape live inference sees), labels
them via :mod:`..services.ml.training_data`, optionally merges the deterministic
bootstrap synthetic set in at a lower example weight (so real logged corrections
dominate while priors on not-yet-exercised heads are not forgotten), trains a new
policy, and writes it as a new ``trapsig-policy`` generation. The running
processor picks up the new generation on its next cycle -- no code deploy needed.

Run it manually, from cron/a scheduled task, or after an
``evaluation/run_matrix.py`` batch. Default is a real run; pass ``--dry-run`` to
train and report without writing a generation.

Works identically on Linux and Windows:  ``python -m backend.app.tools.train_detector``
"""

import argparse
import asyncio
from datetime import datetime, timezone
from typing import Any

from ..config import get_settings
from ..elastic import store as default_store
from ..services.detection.comparison import example_group, grouped_split
from ..services.experiments import event_query
from ..services.ml.bootstrap import DETECTION_TYPES, bootstrap_policy, build_training_examples
from ..services.ml.evaluation import evaluate_policy, evaluate_rule_baseline, feature_means
from ..services.ml.features import FEATURE_SCHEMA_VERSION
from ..services.ml.store import load_latest_policy, save_policy
from ..services.ml.training import TrainingExample, fit_platt, train
from ..services.ml.training_data import build_batch
from ..services.sessionizer import reconstruct_sessions
from ..services.telemetry import is_internal_event

_SKIP_RESULTS = {"INCONCLUSIVE", None}


def split_examples(examples: list[TrainingExample], val_fraction: float, seed: int) -> tuple[list[TrainingExample], list[TrainingExample]]:
    """Deterministic, *grouped* train/validation split.

    Sessions of one experiment are correlated, so a session-level shuffle leaks
    an experiment's style into validation and inflates the promotion gate. Every
    example is grouped by experiment (→ batch → source IP); bootstrap examples
    carry no group and each form their own.
    """
    return grouped_split(examples, example_group, val_fraction, seed)


async def _completed_experiments(store: Any) -> list[dict[str, Any]]:
    try:
        return await store.search_all(
            "trapsig-experiments",
            {"bool": {"should": [{"term": {"status": "completed"}}, {"term": {"status.keyword": "completed"}}], "minimum_should_match": 1}},
            sort=[{"created_at": "asc"}],
            missing_index_is_empty=True,
        )
    except Exception:
        return []


async def _sessions_for(store: Any, experiment: dict[str, Any], timeout_seconds: int) -> list[dict[str, Any]]:
    events = await store.search_all(
        "trapsig-events-*",
        event_query(experiment),
        sort=[{"@timestamp": "asc"}],
        missing_index_is_empty=True,
    )
    return reconstruct_sessions([event for event in events if not is_internal_event(event)], timeout_seconds)


async def collect_batch(store: Any, timeout_seconds: int) -> tuple[list[TrainingExample], int]:
    labeled: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    experiments = await _completed_experiments(store)
    used = 0
    for experiment in experiments:
        if experiment.get("result") in _SKIP_RESULTS:
            continue
        sessions = await _sessions_for(store, experiment, timeout_seconds)
        if sessions:
            labeled.append((experiment, sessions))
            used += 1
    return build_batch(labeled, weight=1.0), used


def _bootstrap_examples(weight: float) -> list[TrainingExample]:
    return [TrainingExample(vector=ex.vector, labels=dict(ex.labels), weight=weight, source="bootstrap") for ex in build_training_examples()]


def _macro_f1(evaluation: dict[str, Any]) -> float | None:
    return evaluation.get("macro_f1") if evaluation else None


async def train_and_store(
    store: Any,
    *,
    merge_bootstrap: bool = True,
    bootstrap_weight: float = 0.3,
    warm_start: bool = True,
    epochs: int = 300,
    learning_rate: float = 0.5,
    l2: float = 0.001,
    val_fraction: float = 0.2,
    min_improvement: float = -0.01,
    force_activate: bool = False,
    seed: int = 1234,
    dry_run: bool = False,
) -> dict[str, Any]:
    settings = get_settings()
    batch, experiment_count = await collect_batch(store, settings.session_timeout_seconds)
    examples = list(batch)
    if merge_bootstrap:
        examples += _bootstrap_examples(bootstrap_weight)

    train_set, val_set = split_examples(examples, val_fraction, seed)

    warm = None
    if warm_start:
        warm = await load_latest_policy(store) or bootstrap_policy()

    trained_at = datetime.now(timezone.utc).isoformat()
    policy_version = f"batch-fs{FEATURE_SCHEMA_VERSION}-n{len(batch)}-{trained_at.replace(':', '').replace('-', '')[:15]}"
    policy = train(
        train_set or examples,
        DETECTION_TYPES,
        epochs=epochs,
        learning_rate=learning_rate,
        l2=l2,
        warm_start=warm,
        policy_version=policy_version,
    )

    # Calibration: per-head Platt scaling on the grouped validation split. Heads
    # without enough held-out evidence stay uncalibrated and are listed as such.
    # Fit on one grouped half of the validation data, measure on the other, so
    # the gate and the reported ECE never see the data calibration was fit on.
    cal_set, eval_set = grouped_split(val_set, example_group, 0.5, seed + 1) if len(val_set) >= 8 else ([], val_set)
    raw_eval = evaluate_policy(policy, eval_set) if eval_set else {}
    calibrated_heads = []
    for kind in DETECTION_TYPES:
        pair = fit_platt(policy, cal_set, kind) if cal_set else None
        if pair is not None:
            policy.calibration[kind] = pair
            calibrated_heads.append(kind)
    val_set = eval_set

    # Promotion gate: a candidate is only activated if it does not regress the
    # held-out macro-F1 versus the current incumbent (the active policy, or the
    # bootstrap when none exists). When we cannot measure (no validation labels),
    # default to activating so adaptation is never silently blocked.
    candidate_eval = evaluate_policy(policy, val_set) if val_set else {}
    incumbent = await load_latest_policy(store) or bootstrap_policy()
    incumbent_eval = evaluate_policy(incumbent, val_set) if val_set else {}
    baseline_eval = evaluate_rule_baseline(val_set) if val_set else {}
    candidate_f1, incumbent_f1 = _macro_f1(candidate_eval), _macro_f1(incumbent_eval)

    if force_activate:
        activate, gate_reason = True, "forced"
    elif candidate_f1 is None and incumbent_f1 is None:
        activate, gate_reason = True, "no held-out signal to compare"
    elif candidate_f1 is None:
        # Never promote a model we could not measure over one we could.
        activate, gate_reason = False, f"candidate not measurable; incumbent macro-F1 {incumbent_f1:.3f}"
    elif incumbent_f1 is None:
        activate, gate_reason = True, "incumbent not measurable"
    else:
        activate = candidate_f1 >= incumbent_f1 + min_improvement
        gate_reason = f"candidate macro-F1 {candidate_f1:.3f} vs incumbent {incumbent_f1:.3f}"

    summary = {
        "policy_version": policy_version,
        "experiments_used": experiment_count,
        "batch_example_count": len(batch),
        "bootstrap_example_count": len(examples) - len(batch),
        "total_example_count": len(examples),
        "train_count": len(train_set or examples),
        "validation_count": len(val_set),
        "warm_started": warm is not None,
        "candidate_macro_f1": candidate_f1,
        "incumbent_macro_f1": incumbent_f1,
        "baseline_macro_f1": _macro_f1(baseline_eval),
        "activated": activate,
        "gate_reason": gate_reason,
        "calibrated_heads": calibrated_heads,
        "ece_before_calibration": raw_eval.get("ece") if raw_eval else None,
        "ece_after_calibration": candidate_eval.get("ece") if candidate_eval else None,
        "dry_run": dry_run,
    }
    if not dry_run:
        stored = await save_policy(
            store,
            policy,
            source="batch",
            training_example_count=len(batch),
            trained_at=trained_at,
            active=activate,
            metrics={"validation": candidate_eval, "validation_uncalibrated": raw_eval, "rule_baseline": baseline_eval, "gate_reason": gate_reason},
            feature_means=feature_means(examples),
            extra={"experiments_used": experiment_count},
        )
        summary["document_id"] = stored["_id"]
    return summary


async def _main(args: argparse.Namespace) -> None:
    try:
        summary = await train_and_store(
            default_store,
            merge_bootstrap=not args.no_merge_bootstrap,
            bootstrap_weight=args.bootstrap_weight,
            warm_start=not args.no_warm_start,
            epochs=args.epochs,
            learning_rate=args.learning_rate,
            l2=args.l2,
            val_fraction=args.val_fraction,
            min_improvement=args.min_improvement,
            force_activate=args.force_activate,
            dry_run=args.dry_run,
        )
    finally:
        await default_store.close()
    for key, value in summary.items():
        print(f"{key}: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-merge-bootstrap", action="store_true", help="train on logged data only, without the synthetic priors")
    parser.add_argument("--bootstrap-weight", type=float, default=0.3, help="per-example weight for merged bootstrap priors (default 0.3)")
    parser.add_argument("--no-warm-start", action="store_true", help="start from zero weights instead of the current/bootstrap policy")
    parser.add_argument("--epochs", type=int, default=300)
    parser.add_argument("--learning-rate", type=float, default=0.5)
    parser.add_argument("--l2", type=float, default=0.001)
    parser.add_argument("--val-fraction", type=float, default=0.2, help="held-out fraction for the promotion gate (default 0.2)")
    parser.add_argument("--min-improvement", type=float, default=-0.01, help="max tolerated macro-F1 regression before a candidate is kept inactive")
    parser.add_argument("--force-activate", action="store_true", help="activate the candidate regardless of the held-out comparison")
    parser.add_argument("--dry-run", action="store_true", help="train and report without writing a new generation")
    asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    main()
