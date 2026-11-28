"""Evaluate a learned policy (and the frozen rule baseline) on labeled examples.

Produces per-head precision/recall/F1, macro averages, and calibration (Brier +
expected calibration error) -- the quantitative evidence that a trained
generation is actually good, and the input to the promotion gate in
``tools/train_detector.py``. Also computes per-feature means for drift detection.
"""

from statistics import fmean, pstdev
from typing import Iterable

from .baseline import rule_baseline_types_from_vector
from .bootstrap import DETECTION_TYPES
from .features import FEATURE_NAMES
from .metrics import brier_score, classification_scores, confusion, expected_calibration_error, macro_average, reliability_bins
from .policy import DEFAULT_THRESHOLD, LinearPolicy
from .training import TrainingExample


def evaluate_policy(policy: LinearPolicy, examples: Iterable[TrainingExample], *, threshold: float = DEFAULT_THRESHOLD) -> dict:
    """Per-head + macro metrics and calibration for a policy over labeled examples."""
    examples = list(examples)
    per_head: dict[str, dict] = {}
    all_true: list[int] = []
    all_prob: list[float] = []
    for head in DETECTION_TYPES:
        labeled = [ex for ex in examples if head in ex.labels]
        if not labeled:
            continue
        y_true = [int(ex.labels[head]) for ex in labeled]
        y_prob = [policy.probability(head, ex.vector) for ex in labeled]
        y_pred = [int(p >= threshold) for p in y_prob]
        scores = classification_scores(confusion(y_true, y_pred))
        scores["brier"] = brier_score(y_true, y_prob)
        scores["ece"] = expected_calibration_error(y_true, y_prob)
        per_head[head] = scores
        all_true.extend(y_true)
        all_prob.extend(y_prob)
    return {
        "policy_version": policy.policy_version,
        "example_count": len(examples),
        "per_head": per_head,
        "macro_f1": macro_average(per_head, "f1"),
        "macro_precision": macro_average(per_head, "precision"),
        "macro_recall": macro_average(per_head, "recall"),
        "brier": brier_score(all_true, all_prob),
        "ece": expected_calibration_error(all_true, all_prob),
        "reliability": reliability_bins(all_true, all_prob),
    }


def evaluate_rule_baseline(examples: Iterable[TrainingExample]) -> dict:
    """Per-head + macro metrics for the frozen rule baseline (no probabilities)."""
    examples = list(examples)
    predictions = [rule_baseline_types_from_vector(ex.vector) for ex in examples]
    per_head: dict[str, dict] = {}
    for head in DETECTION_TYPES:
        labeled = [(ex, pred) for ex, pred in zip(examples, predictions, strict=True) if head in ex.labels]
        if not labeled:
            continue
        y_true = [int(ex.labels[head]) for ex, _ in labeled]
        y_pred = [int(head in pred) for _, pred in labeled]
        per_head[head] = classification_scores(confusion(y_true, y_pred))
    return {
        "predictor": "rule-baseline",
        "example_count": len(examples),
        "per_head": per_head,
        "macro_f1": macro_average(per_head, "f1"),
        "macro_precision": macro_average(per_head, "precision"),
        "macro_recall": macro_average(per_head, "recall"),
    }


def feature_means(examples: Iterable[TrainingExample]) -> dict[str, float]:
    """Mean of each feature across examples (training-time reference for drift)."""
    examples = list(examples)
    if not examples:
        return {name: 0.0 for name in FEATURE_NAMES}
    return {name: fmean(ex.vector[index] for ex in examples) for index, name in enumerate(FEATURE_NAMES)}


def population_stability(reference: dict[str, float], current: dict[str, float], examples: Iterable[TrainingExample]) -> dict[str, float]:
    """Standardized per-feature mean shift (drift signal) between two datasets.

    A simple, dependency-free drift measure: |mean_current - mean_reference| in
    units of the current data's per-feature standard deviation. Large values flag
    features whose live distribution has moved away from what the policy trained
    on, suggesting retraining.
    """
    examples = list(examples)
    drift: dict[str, float] = {}
    for index, name in enumerate(FEATURE_NAMES):
        values = [ex.vector[index] for ex in examples]
        spread = pstdev(values) if len(values) > 1 else 0.0
        delta = abs(current.get(name, 0.0) - reference.get(name, 0.0))
        drift[name] = (delta / spread) if spread > 1e-9 else (0.0 if delta < 1e-9 else float("inf"))
    return drift
