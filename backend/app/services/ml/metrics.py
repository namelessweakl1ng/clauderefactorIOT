"""Pure classification + calibration metrics for evaluating a learned policy.

No third-party dependency (no numpy/sklearn): a final-year research platform on a
laptop/Pi should not need a heavy ML stack to report precision, recall, F1 and
calibration. All functions are pure and deterministic.
"""

from typing import Iterable


def confusion(y_true: Iterable[int], y_pred: Iterable[int]) -> dict[str, int]:
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, y_pred, strict=True):
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def classification_scores(cm: dict[str, int]) -> dict[str, float | None]:
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    # 2TP/(2TP+FP+FN): defined whenever the head has support or false alarms, so
    # a head that never fires scores 0 instead of silently dropping out of macro-F1.
    f1 = _ratio(2 * tp, 2 * tp + fp + fn)
    return {
        "support": tp + fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": _ratio(tp + tn, tp + fp + fn + tn),
        "specificity": _ratio(tn, tn + fp),
    }


def brier_score(y_true: Iterable[int], y_prob: Iterable[float]) -> float | None:
    """Mean squared error between predicted probabilities and outcomes."""
    total = 0.0
    count = 0
    for actual, probability in zip(y_true, y_prob, strict=True):
        total += (probability - actual) ** 2
        count += 1
    return total / count if count else None


def reliability_bins(y_true: list[int], y_prob: list[float], bins: int = 10) -> list[dict[str, float | int]]:
    """Calibration curve: per-bin mean predicted prob vs observed frequency."""
    buckets: list[dict[str, float | int]] = []
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        picked = [(a, p) for a, p in zip(y_true, y_prob, strict=True) if (p >= low and (p < high or (index == bins - 1 and p <= high)))]
        if not picked:
            continue
        mean_predicted = sum(p for _, p in picked) / len(picked)
        observed = sum(a for a, _ in picked) / len(picked)
        buckets.append({"bin_low": low, "bin_high": high, "count": len(picked), "mean_predicted": mean_predicted, "observed_frequency": observed})
    return buckets


def expected_calibration_error(y_true: list[int], y_prob: list[float], bins: int = 10) -> float | None:
    """Weighted average gap between confidence and accuracy across bins."""
    total = len(y_true)
    if not total:
        return None
    error = 0.0
    for bucket in reliability_bins(y_true, y_prob, bins):
        weight = bucket["count"] / total
        error += weight * abs(bucket["mean_predicted"] - bucket["observed_frequency"])
    return error


def macro_average(per_head: dict[str, dict[str, float | None]], field: str) -> float | None:
    """Mean of a per-head score across heads that have a value for it."""
    values = [float(value) for scores in per_head.values() if (value := scores.get(field)) is not None]
    return sum(values) / len(values) if values else None
