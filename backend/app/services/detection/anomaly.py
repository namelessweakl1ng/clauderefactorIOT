"""Deterministic Isolation Forest for novelty detection over session features.

Why this algorithm: everything that reaches a honeypot is unsolicited, so "normal
vs attack" is the wrong question for an unsupervised engine. The useful question
is *"is this session unlike what the sensor fleet has seen before?"* -- i.e.
novelty that neither rules nor the supervised heads were written for. Isolation
Forest (Liu, Ting & Zhou, ICDM 2008) answers exactly that, needs no labels,
handles mixed-scale count features without normalisation, and scores in
O(trees × depth) -- microseconds per session in pure Python, so no numpy or
scikit-learn is added to the 256 MB backend container.

Explanations are a **heuristic** and are labelled as such: for the scored
session we accumulate, per feature, ``1 / (depth + 1)`` for every split on that
feature along its isolation path (features that isolate the point early get more
credit), and report the observed value next to the training median. This is
in the spirit of depth-based attributions (cf. DIFFI) but is not a faithful
Shapley attribution.

**Out-of-range modification (documented deviation from the paper).** Standard
iForest cannot see novelty in a feature that was constant in training (e.g. shell
commands when no training session had any), nor values beyond the training range:
such points simply follow the extreme branch. Each tree therefore also stores
its subsample's bounding box; a point outside it on any feature is treated as
isolated by one split (path length 1). Training rows outside some trees'
subsamples experience the same rule, so the quantile threshold below still
calibrates the alert rate on the training distribution.

Scores follow the paper: ``s(x) = 2 ** (-E[h(x)] / c(n))``; ~0.5 is ordinary,
→1 is easily isolated. The alert threshold is the training-score quantile
``1 - contamination`` (default 0.99), floored at 0.6, so it is reproducible from
the stored model.
"""

from __future__ import annotations

import math
import random
import time
from datetime import datetime, timezone
from hashlib import sha256
from statistics import median
from typing import Any, Sequence

from ..ml.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, describe_feature, feature_vector, raw_feature_map

ANOMALY_INDEX = "trapsig-model-anomaly"
_EULER = 0.5772156649


def average_path_length(n: int) -> float:
    """c(n): expected path length of an unsuccessful BST search over n points."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + _EULER) - 2.0 * (n - 1) / n


# A tree is a flat list of nodes: internal = [feature, split, left, right], leaf = [-1, size].
Tree = list[list[float]]


def _build(rng: random.Random, rows: Sequence[Sequence[float]], depth: int, limit: int, nodes: Tree) -> int:
    index = len(nodes)
    if depth >= limit or len(rows) <= 1:
        nodes.append([-1, float(len(rows))])
        return index
    dims = len(rows[0])
    candidates = [d for d in range(dims) if min(r[d] for r in rows) < max(r[d] for r in rows)]
    if not candidates:
        nodes.append([-1, float(len(rows))])
        return index
    feature = rng.choice(candidates)
    low = min(r[feature] for r in rows)
    high = max(r[feature] for r in rows)
    split = rng.uniform(low, high)
    nodes.append([float(feature), split, -1.0, -1.0])
    left_rows = [r for r in rows if r[feature] < split]
    right_rows = [r for r in rows if r[feature] >= split]
    nodes[index][2] = float(_build(rng, left_rows, depth + 1, limit, nodes))
    nodes[index][3] = float(_build(rng, right_rows, depth + 1, limit, nodes))
    return index


def _path(tree: Tree, x: Sequence[float]) -> tuple[float, list[tuple[int, int]]]:
    """Return (path length incl. c(size) leaf adjustment, [(feature, depth), ...])."""
    node, depth = 0, 0
    used: list[tuple[int, int]] = []
    while True:
        current = tree[node]
        if current[0] < 0:
            return depth + average_path_length(int(current[1])), used
        feature = int(current[0])
        used.append((feature, depth))
        node = int(current[2] if x[feature] < current[1] else current[3])
        depth += 1


class IsolationForest:
    def __init__(
        self,
        trees: list[Tree],
        *,
        sample_size: int,
        threshold: float,
        medians: list[float],
        feature_names: Sequence[str] = FEATURE_NAMES,
        model_version: str = "unversioned",
        trained_on: int = 0,
        seed: int = 0,
        bounds: list[tuple[list[float], list[float]]] | None = None,
    ) -> None:
        self.trees = trees
        self.bounds = bounds or []
        self.sample_size = sample_size
        self.threshold = threshold
        self.medians = list(medians)
        self.feature_names = tuple(feature_names)
        self.model_version = model_version
        self.trained_on = trained_on
        self.seed = seed

    @classmethod
    def fit(
        cls,
        vectors: Sequence[Sequence[float]],
        *,
        n_trees: int = 64,
        sample_size: int = 128,
        contamination: float = 0.01,
        seed: int = 20261126,
        feature_names: Sequence[str] = FEATURE_NAMES,
    ) -> "IsolationForest":
        if len(vectors) < 8:
            raise ValueError("isolation forest needs at least 8 training sessions")
        rng = random.Random(seed)
        rows = [list(map(float, v)) for v in vectors]
        size = min(sample_size, len(rows))
        limit = math.ceil(math.log2(max(size, 2)))
        trees: list[Tree] = []
        bounds: list[tuple[list[float], list[float]]] = []
        for _ in range(n_trees):
            sample = rng.sample(rows, size)
            nodes: Tree = []
            _build(rng, sample, 0, limit, nodes)
            trees.append(nodes)
            dims = range(len(sample[0]))
            bounds.append(([min(r[d] for r in sample) for d in dims], [max(r[d] for r in sample) for d in dims]))
        medians = [median(r[d] for r in rows) for d in range(len(rows[0]))]
        model = cls(trees, sample_size=size, threshold=1.0, medians=medians, feature_names=feature_names, trained_on=len(rows), seed=seed, bounds=bounds)
        scores = sorted(model.score(r) for r in rows)
        quantile = scores[min(len(scores) - 1, int(math.ceil((1 - contamination) * len(scores))) - 1)]
        model.threshold = round(max(0.6, quantile), 6)
        digest = sha256(f"{seed}|{n_trees}|{size}|{len(rows)}|{model.threshold}".encode()).hexdigest()[:10]
        model.model_version = f"iforest-fs{FEATURE_SCHEMA_VERSION}-{digest}"
        return model

    def _outside(self, tree_index: int, x: Sequence[float]) -> int | None:
        mins, maxs = self.bounds[tree_index]
        for feature, value in enumerate(x):
            if value < mins[feature] or value > maxs[feature]:
                return feature
        return None

    def _length(self, tree_index: int, x: Sequence[float]) -> float:
        if self.bounds and self._outside(tree_index, x) is not None:
            return 1.0
        return _path(self.trees[tree_index], x)[0]

    def score(self, x: Sequence[float]) -> float:
        lengths = [self._length(index, x) for index in range(len(self.trees))]
        expected = sum(lengths) / len(lengths)
        normaliser = average_path_length(self.sample_size) or 1.0
        return 2.0 ** (-expected / normaliser)

    def attribution(self, x: Sequence[float]) -> list[tuple[str, float]]:
        credit = [0.0] * len(self.feature_names)
        for index, tree in enumerate(self.trees):
            outside = self._outside(index, x) if self.bounds else None
            if outside is not None:
                credit[outside] += 1.0
                continue
            for feature, depth in _path(tree, x)[1]:
                credit[feature] += 1.0 / (depth + 1)
        total = sum(credit) or 1.0
        ranked = sorted(((self.feature_names[i], credit[i] / total) for i in range(len(credit))), key=lambda item: item[1], reverse=True)
        return ranked

    def score_session(self, session: dict[str, Any]) -> dict[str, Any]:
        vector = feature_vector(session)
        score = self.score(vector)
        raw = raw_feature_map(session)
        features: list[dict[str, Any]] = []
        unusual: list[str] = []
        for name, share in self.attribution(vector)[:4]:
            index = self.feature_names.index(name)
            features.append(
                {
                    "feature": name,
                    "value": raw.get(name, 0.0),
                    "training_median_scaled": round(self.medians[index], 6),
                    "observed_scaled": round(vector[index], 6),
                    "attribution_share": round(share, 4),
                    "description": describe_feature(name, raw.get(name, 0.0)),
                }
            )
            if abs(vector[index] - self.medians[index]) > 1e-9 and len(unusual) < 3:
                unusual.append(describe_feature(name, raw.get(name, 0.0)))
        reason = (
            f"Session is unusually easy to isolate (score {score:.2f} ≥ {self.threshold:.2f}); "
            + ("most distinctive: " + "; ".join(unusual) + "." if unusual else "no single feature dominates.")
            + " Attribution is a depth-weighted heuristic."
        )
        return {"anomalous": score >= self.threshold, "score": round(score, 6), "features": features, "reason": reason}

    def to_document(self, **metadata: Any) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": list(self.feature_names),
            "sample_size": self.sample_size,
            "threshold": self.threshold,
            "medians": self.medians,
            "trained_on": self.trained_on,
            "seed": self.seed,
            "trees": self.trees,
            "bounds": [[list(lo), list(hi)] for lo, hi in self.bounds],
            **metadata,
        }

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "IsolationForest":
        return cls(
            [[list(map(float, node)) for node in tree] for tree in document["trees"]],
            sample_size=int(document["sample_size"]),
            threshold=float(document["threshold"]),
            medians=[float(v) for v in document["medians"]],
            feature_names=tuple(document.get("feature_names", FEATURE_NAMES)),
            model_version=str(document.get("model_version", "unversioned")),
            trained_on=int(document.get("trained_on", 0)),
            seed=int(document.get("seed", 0)),
            bounds=[([float(v) for v in lo], [float(v) for v in hi]) for lo, hi in document.get("bounds") or []],
        )


_cache: dict[str, Any] = {"model": None, "loaded_at": 0.0}
_RELOAD_SECONDS = 300.0


async def load_latest_anomaly_model(store: Any, *, force: bool = False) -> IsolationForest | None:
    """Newest *active* anomaly model, cached for five minutes (documents are large).

    Returns ``None`` when none exists; the anomaly engine is then simply inactive
    (there is no synthetic cold-start for novelty detection -- a model trained on
    invented data would define "novel" arbitrarily).
    """
    now = time.monotonic()
    if not force and _cache["loaded_at"] and now - _cache["loaded_at"] < _RELOAD_SECONDS:
        return _cache["model"]
    try:
        try:
            documents = await store.search(ANOMALY_INDEX, size=5, sort_field="trained_at", missing_index_is_empty=True)
        except TypeError:
            documents = await store.search(ANOMALY_INDEX, size=5, sort_field="trained_at")
    except Exception:
        return _cache["model"]
    model = None
    for document in documents or []:
        if document.get("active", True) and document.get("trees"):
            if document.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
                continue
            try:
                model = IsolationForest.from_document(document)
            except (KeyError, TypeError, ValueError):
                model = None
            break
    _cache.update(model=model, loaded_at=now)
    return model


async def save_anomaly_model(store: Any, model: IsolationForest, *, source: str, active: bool = True, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    trained_at = datetime.now(timezone.utc).isoformat()
    document = model.to_document(source=source, trained_at=trained_at, active=active, trapsig={"schema_version": "1"}, **(extra or {}))
    identifier = "ANM-" + sha256(f"{model.model_version}|{trained_at}".encode()).hexdigest()[:16]
    await store.save(ANOMALY_INDEX, identifier, document)
    _cache.update(model=model if active else _cache["model"], loaded_at=time.monotonic())
    return {**document, "_id": identifier}
