"""Interpretable multi-label linear policy: one logistic head per detection type.

All heads share one feature vector (see :mod:`.features`). Each head is a plain
logistic unit ``p = sigmoid(w . x + b)`` and fires when ``p >= threshold``. This
is deliberately simple and dependency-free (pure Python, no numpy, no GPU):

* it stays interpretable -- the per-feature contribution ``weight * value`` is a
  number we can sort and render as the detection's human-readable reason, which
  preserves the project's "reasons and evidence IDs, no opaque score" contract;
* it trains in milliseconds on a laptop or Pi;
* it maps cleanly onto a *contextual bandit with batch policy-gradient updates*.
  For the deterministic +/-1 correctness reward used here, that update rule
  reduces exactly to reward-weighted logistic regression -- we say so plainly in
  :mod:`.training` rather than dressing up ordinary supervised correction.

The policy carries no training logic; :mod:`.training` fits the weights and
:mod:`.bootstrap` seeds the cold-start generation. Weights are serialized to (and
restored from) the ``trapsig-policy`` Elasticsearch index, never a local file.
"""

from math import exp
from typing import Any

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, describe_feature, feature_vector, raw_feature_map

DEFAULT_THRESHOLD = 0.5

# Confidence -> existing severity vocabulary, by fixed bands.
_SEVERITY_BANDS = ((0.6, "low"), (0.75, "medium"), (0.9, "high"))


def sigmoid(z: float) -> float:
    # Numerically stable logistic.
    if z >= 0:
        return 1.0 / (1.0 + exp(-z))
    expz = exp(z)
    return expz / (1.0 + expz)


def severity_for(confidence: float) -> str:
    for ceiling, label in _SEVERITY_BANDS:
        if confidence < ceiling:
            return label
    return "critical"


class LinearPolicy:
    """A frozen set of per-type logistic heads over a fixed feature schema."""

    def __init__(
        self,
        weights: dict[str, list[float]],
        biases: dict[str, float],
        *,
        feature_names: tuple[str, ...] = FEATURE_NAMES,
        policy_version: str = "unversioned",
        feature_schema_version: str = FEATURE_SCHEMA_VERSION,
        calibration: dict[str, tuple[float, float]] | None = None,
    ) -> None:
        self.feature_names = tuple(feature_names)
        self.weights = {kind: list(vector) for kind, vector in weights.items()}
        self.biases = dict(biases)
        self.policy_version = policy_version
        self.feature_schema_version = feature_schema_version
        # Per-head Platt scaling (a, b): p = sigmoid(a * logit + b), fitted on
        # held-out data by tools/train_detector.py. Absent = raw (uncalibrated).
        self.calibration = {kind: (float(a), float(b)) for kind, (a, b) in (calibration or {}).items()}

    @property
    def detection_types(self) -> list[str]:
        return sorted(self.weights)

    def logit(self, kind: str, vector: list[float]) -> float:
        weight = self.weights[kind]
        return self.biases.get(kind, 0.0) + sum(w * x for w, x in zip(weight, vector, strict=True))

    def probability(self, kind: str, vector: list[float]) -> float:
        z = self.logit(kind, vector)
        if kind in self.calibration:
            a, b = self.calibration[kind]
            z = a * z + b
        return sigmoid(z)

    def is_calibrated(self, kind: str) -> bool:
        return kind in self.calibration

    def probabilities(self, vector: list[float]) -> dict[str, float]:
        return {kind: self.probability(kind, vector) for kind in self.weights}

    def contributions(self, kind: str, vector: list[float]) -> list[tuple[str, float]]:
        """(feature_name, weight*value) pairs, most influential first."""
        weight = self.weights[kind]
        pairs = [(name, weight[i] * vector[i]) for i, name in enumerate(self.feature_names)]
        pairs.sort(key=lambda item: abs(item[1]), reverse=True)
        return pairs

    def reason(self, kind: str, session: dict[str, Any], vector: list[float], *, top_n: int = 3) -> str:
        """Build a reason string from the top positively-contributing features."""
        raw = raw_feature_map(session)
        phrases = []
        for name, contribution in self.contributions(kind, vector):
            if contribution <= 0 or raw.get(name, 0.0) <= 0:
                continue
            phrases.append(describe_feature(name, raw.get(name, 0.0)))
            if len(phrases) >= top_n:
                break
        if not phrases:
            return "learned policy fired on the combined session feature profile."
        return f"{'; '.join(phrases)} contributed most to this detection."

    def to_document(self, **metadata: Any) -> dict[str, Any]:
        """Serialize for storage in ``trapsig-policy`` (metadata merged in)."""
        return {
            "policy_version": self.policy_version,
            "feature_schema_version": self.feature_schema_version,
            "feature_names": list(self.feature_names),
            "weights": {kind: list(vector) for kind, vector in self.weights.items()},
            "biases": dict(self.biases),
            "calibration": {kind: list(pair) for kind, pair in self.calibration.items()},
            **metadata,
        }

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "LinearPolicy":
        return cls(
            weights={kind: [float(v) for v in vector] for kind, vector in document["weights"].items()},
            biases={kind: float(v) for kind, v in document.get("biases", {}).items()},
            feature_names=tuple(document.get("feature_names", FEATURE_NAMES)),
            policy_version=document.get("policy_version", "unversioned"),
            feature_schema_version=document.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
            calibration={kind: (pair[0], pair[1]) for kind, pair in (document.get("calibration") or {}).items()},
        )

    def evaluate(
        self,
        session: dict[str, Any],
        *,
        thresholds: dict[str, float] | None = None,
        threshold_scale: float = 1.0,
    ) -> list[dict[str, Any]]:
        """Return fired heads as detection fragments (type, confidence, reason, ...).

        ``threshold_scale`` lets the hardening layer lower the effective firing
        threshold per source IP (elevated/locked posture) without retraining.
        """
        vector = feature_vector(session)
        thresholds = thresholds or {}
        fired: list[dict[str, Any]] = []
        for kind in self.detection_types:
            confidence = self.probability(kind, vector)
            threshold = thresholds.get(kind, DEFAULT_THRESHOLD) * threshold_scale
            if confidence >= threshold:
                fired.append(
                    {
                        "type": kind,
                        "confidence": round(confidence, 6),
                        "severity": severity_for(confidence),
                        "reason": self.reason(kind, session, vector),
                        "policy_version": self.policy_version,
                        "effective_threshold": round(threshold, 6),
                    }
                )
        return fired
