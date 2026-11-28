"""Experiment-lab analytics: arm comparison with uncertainty, reproducible bundles.

Answers questions of the form *"did configuration B change detection versus
baseline A?"* from completed experiments only:

* Each **arm** is a set of conclusive experiments selected by ``condition`` label
  (and optionally batch). INCONCLUSIVE runs are counted and reported, never
  folded into denominators (the project's established semantics).
* Recall (TP/(TP+FN)) and false-positive rate (FP/(FP+TN)) are reported with
  **Wilson 95 % intervals**; differences are tested with a **two-sided Fisher
  exact test**, which is valid at the small n typical of lab runs.
* Arms whose detector/config fingerprints differ are flagged: a difference may
  then come from the software, not the condition.
* The conclusion string is deliberately conservative.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from math import comb, sqrt
from statistics import median
from typing import Any, Iterable

from .evaluation import classification_metrics, evaluation_config_fingerprint

RESULTS = ("TP", "FN", "FP", "TN", "INCONCLUSIVE")


def wilson_interval(successes: int, total: int, z: float = 1.959964) -> tuple[float, float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    # At p = 0 or 1 the bound is exactly 0 / 1; avoid float residue like 0.9999999999999999.
    low = 0.0 if successes == 0 else max(0.0, centre - margin)
    high = 1.0 if successes == total else min(1.0, centre + margin)
    return low, high


def fisher_exact(a: int, b: int, c: int, d: int) -> float | None:
    """Two-sided Fisher exact p-value for the 2×2 table [[a, b], [c, d]]."""
    row1, row2, col1 = a + b, c + d, a + c
    n = row1 + row2
    if n == 0 or row1 == 0 or row2 == 0 or col1 == 0 or col1 == n:
        return None
    denominator = comb(n, col1)

    def probability(x: int) -> float:
        return comb(row1, x) * comb(row2, col1 - x) / denominator

    observed = probability(a)
    low, high = max(0, col1 - row2), min(row1, col1)
    p = sum(prob for x in range(low, high + 1) if (prob := probability(x)) <= observed * (1 + 1e-9))
    return min(1.0, p)


def arm_summary(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    records = list(records)
    counts = {name: sum(r.get("result") == name for r in records) for name in RESULTS}
    tp, fn, fp, tn = counts["TP"], counts["FN"], counts["FP"], counts["TN"]
    latencies = [r["detection_latency_seconds"] for r in records if r.get("result") == "TP" and isinstance(r.get("detection_latency_seconds"), (int, float))]
    fingerprints = sorted({fp_ for r in records if (fp_ := r.get("evaluation_config_fingerprint") or evaluation_config_fingerprint(r))})
    detectors = sorted({str(r.get("detector_ruleset_version")) for r in records if r.get("detector_ruleset_version")})
    return {
        "experiments": len(records),
        "counts": counts,
        "metrics": classification_metrics(tp, fn, fp, tn),
        "recall_ci95": wilson_interval(tp, tp + fn),
        "false_positive_rate_ci95": wilson_interval(fp, fp + tn),
        "detection_latency_median_seconds": median(latencies) if latencies else None,
        "scenarios": sorted({r.get("scenario_id") for r in records if r.get("scenario_id")}),
        "config_fingerprints": fingerprints,
        "detector_versions": detectors,
        "experiment_ids": [r.get("experiment_id") for r in records],
    }


def compare_arms(
    a_records: list[dict[str, Any]], b_records: list[dict[str, Any]], *, labels: tuple[str, str] = ("A", "B"), alpha: float = 0.05
) -> dict[str, Any]:
    a, b = arm_summary(a_records), arm_summary(b_records)
    ca, cb = a["counts"], b["counts"]
    recall_p = fisher_exact(ca["TP"], ca["FN"], cb["TP"], cb["FN"])
    fpr_p = fisher_exact(ca["FP"], ca["TN"], cb["FP"], cb["TN"])

    def delta(key: str) -> float | None:
        left, right = a["metrics"].get(key), b["metrics"].get(key)
        return None if left is None or right is None else right - left

    shared_scenarios = sorted(set(a["scenarios"]) & set(b["scenarios"]))
    warnings = []
    if a["detector_versions"] != b["detector_versions"]:
        warnings.append("arms ran different detector versions; a difference may come from software, not the condition")
    if not shared_scenarios:
        warnings.append("arms share no scenario; they do not measure the same attacks")
    if min(ca["TP"] + ca["FN"], cb["TP"] + cb["FN"]) < 5:
        warnings.append("fewer than 5 conclusive attack runs in an arm; recall estimates are very uncertain")
    if a["counts"]["INCONCLUSIVE"] or b["counts"]["INCONCLUSIVE"]:
        warnings.append("inconclusive runs were excluded from denominators (see counts)")
    recall_delta = delta("recall")
    if recall_p is None or recall_delta is None:
        conclusion = "Not measurable: an arm has no conclusive attack runs."
    elif recall_p < alpha:
        direction = "higher" if recall_delta > 0 else "lower"
        conclusion = f"{labels[1]} recall is {direction} than {labels[0]} by {abs(recall_delta):.2f} (Fisher p={recall_p:.3g} < {alpha})."
    else:
        conclusion = (
            f"No statistically significant recall difference between {labels[0]} and {labels[1]} (Fisher p={recall_p:.3g}); insufficient evidence of an effect."
        )
    return {
        "labels": list(labels),
        "arms": {labels[0]: a, labels[1]: b},
        "delta": {"recall": recall_delta, "precision": delta("precision"), "false_positive_rate": delta("false_positive_rate"), "f1": delta("f1")},
        "tests": {"recall_fisher_p": recall_p, "false_positive_rate_fisher_p": fpr_p, "alpha": alpha},
        "shared_scenarios": shared_scenarios,
        "warnings": warnings,
        "conclusion": conclusion,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def dataset_bundle(
    experiment: dict[str, Any], events: list[dict[str, Any]], sessions: list[dict[str, Any]], detections: list[dict[str, Any]]
) -> dict[str, Any]:
    """Self-describing, hash-verified research bundle for one experiment.

    Raw events are the immutable indexed documents; derived records are included
    as materialized so a reader can re-run detection over the events and compare.
    """
    clean = lambda docs: [{k: v for k, v in d.items() if k != "_id"} for d in docs]  # noqa: E731
    parts = {
        "experiment": {k: v for k, v in experiment.items() if k != "_id"},
        "ground_truth": experiment.get("ground_truth"),
        "events": clean(sorted(events, key=lambda e: (str(e.get("@timestamp")), str((e.get("event") or {}).get("id"))))),
        "sessions": clean(sessions),
        "detections": clean(detections),
    }
    manifest = {
        "format": "trapsig-dataset/1",
        "experiment_id": experiment.get("experiment_id"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "counts": {name: len(value) if isinstance(value, list) else int(value is not None) for name, value in parts.items()},
        "sha256": {name: _digest(value) for name, value in parts.items()},
        "schema_versions": sorted({str((e.get("trapsig") or {}).get("schema_version")) for e in events}),
        "config_snapshot": experiment.get("config_snapshot"),
        "labels": {"trial_kind": experiment.get("trial_kind"), "expected_detection": experiment.get("expected_detection"), "result": experiment.get("result")},
        "verify": "sha256 is over json.dumps(part, sort_keys=True, separators=(',', ':'))",
    }
    return {"manifest": manifest, **parts}
