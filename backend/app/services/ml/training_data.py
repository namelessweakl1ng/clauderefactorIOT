"""Build labeled training examples from completed experiments + linked sessions.

Ground truth already exists and is reward-ready: ``experiments.py::correlate``
classifies each completed experiment against its known ``expected_detection``.
This module turns that into supervised labels for batch retraining:

* **Attack** trial -> label ``1`` for the ``expected_detection`` head (regardless
  of whether the original run was a TP or FN -- training should push toward the
  correct label). Other heads are left *unknown* for that example and skipped in
  their gradient step, because an attack only establishes ground truth for the
  one head it was designed to trigger.
* **Control** trial -> label ``0`` for *every* head (nothing should have fired).
* **INCONCLUSIVE** -> skipped entirely (no usable ground truth).

Examples are built from sessions reconstructed from raw ``trapsig-events-*`` with
``events`` still attached (same shape live inference sees), so there is no
train/serve feature skew. The CLI in ``tools/train_detector.py`` does the raw-event
fetch and reconstruction; this module is the pure, testable labeling step.
"""

from typing import Any, Iterable

from .bootstrap import DETECTION_TYPES
from .features import feature_vector
from .training import TrainingExample

_SKIP_RESULTS = {"INCONCLUSIVE", None}


def examples_for_experiment(
    experiment: dict[str, Any],
    sessions: Iterable[dict[str, Any]],
    *,
    weight: float = 1.0,
) -> list[TrainingExample]:
    """Return labeled examples for one completed experiment.

    ``sessions`` are full (events-attached) sessions for this experiment's
    attacker/time window; the experiment's recorded ``session_ids`` narrow them to
    the ones actually linked, falling back to all supplied sessions.
    """
    if experiment.get("result") in _SKIP_RESULTS:
        return []
    trial_kind = experiment.get("trial_kind", experiment.get("scenario_kind", "attack"))
    linked = set(experiment.get("session_ids") or [])
    chosen = [s for s in sessions if not linked or s.get("session_id") in linked]
    if not chosen:
        return []

    if trial_kind == "control":
        labels = {kind: 0 for kind in DETECTION_TYPES}
    else:
        expected = experiment.get("expected_detection")
        if not expected:
            return []
        labels = {expected: 1}

    experiment_id = experiment.get("experiment_id")
    return [
        TrainingExample(
            vector=feature_vector(session),
            labels=dict(labels),
            weight=weight,
            source="batch",
            metadata={"experiment_id": experiment_id, "session_id": session.get("session_id")},
        )
        for session in chosen
    ]


def build_batch(
    labeled: Iterable[tuple[dict[str, Any], list[dict[str, Any]]]],
    *,
    weight: float = 1.0,
) -> list[TrainingExample]:
    """Flatten (experiment, sessions) pairs into one labeled training batch."""
    examples: list[TrainingExample] = []
    for experiment, sessions in labeled:
        examples.extend(examples_for_experiment(experiment, sessions, weight=weight))
    return examples
