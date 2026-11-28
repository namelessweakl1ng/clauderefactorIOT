"""Offline/batch policy training: reward-weighted logistic / policy-gradient fit.

This is the *only* place weights change, and it is deliberately offline: a CLI or
scheduled job calls :func:`train`, writes a new ``trapsig-policy`` generation, and
the live processor then picks it up on its next cycle. No weight update ever
happens inline on the request path.

Framing, stated plainly: each detection head is a contextual-bandit arm with a
deterministic +/-1 correctness reward (did firing match ground truth?). The
batch policy-gradient update for that reward reduces exactly to reward-weighted
logistic regression, so that is what we implement -- full-batch gradient descent
on the weighted log-loss with an L2 penalty. It is fully deterministic (no
wall-clock-seeded randomness), so repeated boots and tests behave identically.
"""

from dataclasses import dataclass, field
from typing import Iterable

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from .policy import LinearPolicy, sigmoid


@dataclass
class TrainingExample:
    """One labeled session.

    ``labels`` maps a detection type to 0/1. A head absent from the map is
    "unknown" for this example and is skipped in that head's gradient (real
    logged experiments usually only know the truth for one head); synthetic
    bootstrap examples fill every head because their ground truth is complete.
    """

    vector: list[float]
    labels: dict[str, int]
    weight: float = 1.0
    source: str = "unknown"
    metadata: dict[str, object] = field(default_factory=dict)


def _zeros(n: int) -> list[float]:
    return [0.0] * n


def train(
    examples: Iterable[TrainingExample],
    detection_types: Iterable[str],
    *,
    epochs: int = 300,
    learning_rate: float = 0.5,
    l2: float = 0.001,
    warm_start: LinearPolicy | None = None,
    policy_version: str = "untagged",
    feature_names: tuple[str, ...] = FEATURE_NAMES,
) -> LinearPolicy:
    """Fit one logistic head per detection type and return a :class:`LinearPolicy`.

    ``warm_start`` seeds the weights (e.g. continue from the bootstrap policy so
    types not yet exercised by real data keep their priors); otherwise heads
    start at zero.
    """
    examples = list(examples)
    types = sorted(set(detection_types))
    dim = len(feature_names)

    weights: dict[str, list[float]] = {}
    biases: dict[str, float] = {}
    for kind in types:
        if warm_start is not None and kind in warm_start.weights and len(warm_start.weights[kind]) == dim:
            weights[kind] = list(warm_start.weights[kind])
            biases[kind] = warm_start.biases.get(kind, 0.0)
        else:
            weights[kind] = _zeros(dim)
            biases[kind] = 0.0

    for kind in types:
        labeled = [ex for ex in examples if kind in ex.labels]
        total_weight = sum(ex.weight for ex in labeled)
        if total_weight <= 0:
            continue
        weight_vector = weights[kind]
        bias = biases[kind]
        for _ in range(epochs):
            grad_w = _zeros(dim)
            grad_b = 0.0
            for ex in labeled:
                activation = bias + sum(w * x for w, x in zip(weight_vector, ex.vector, strict=True))
                error = ex.labels[kind] - sigmoid(activation)
                scaled = ex.weight * error
                for i, x in enumerate(ex.vector):
                    grad_w[i] += scaled * x
                grad_b += scaled
            for i in range(dim):
                weight_vector[i] += learning_rate * (grad_w[i] / total_weight - l2 * weight_vector[i])
            bias += learning_rate * (grad_b / total_weight)
        biases[kind] = bias

    return LinearPolicy(
        weights=weights,
        biases=biases,
        feature_names=feature_names,
        policy_version=policy_version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def fit_platt(
    policy: LinearPolicy, examples: Iterable[TrainingExample], kind: str, *, epochs: int = 400, learning_rate: float = 0.1
) -> tuple[float, float] | None:
    """Fit Platt scaling for one head on held-out examples; None when not identifiable.

    Requires at least 10 labeled examples with both classes present, otherwise
    the fit would be noise and the head stays uncalibrated (and is reported so).
    """
    labeled = [(policy.logit(kind, ex.vector), ex.labels[kind]) for ex in examples if kind in ex.labels]
    positives = sum(label for _, label in labeled)
    if len(labeled) < 10 or positives == 0 or positives == len(labeled):
        return None
    a, b = 1.0, 0.0
    n = float(len(labeled))
    for _ in range(epochs):
        grad_a = grad_b = 0.0
        for z, label in labeled:
            error = sigmoid(a * z + b) - label
            grad_a += error * z
            grad_b += error
        a -= learning_rate * grad_a / n
        b -= learning_rate * grad_b / n
    return (round(a, 6), round(b, 6))
