"""Grouped evaluation framework: splits, metrics semantics, end-to-end report."""

import pytest

from backend.app.services.detection.comparison import (
    ENGINES,
    LabeledSession,
    compare,
    evaluate_predictions,
    example_group,
    group_kfold,
    grouped_split,
    labeled_from_experiments,
    scores,
    synthetic_corpus,
)
from backend.app.services.ml.training import TrainingExample


def test_group_kfold_never_splits_a_group_and_is_deterministic():
    groups = [f"g{i % 7}" for i in range(50)]
    folds = group_kfold(groups, 4, seed=1)
    assert folds == group_kfold(groups, 4, seed=1)
    assert sorted(i for fold in folds for i in fold) == list(range(50))
    for fold in folds:
        fold_groups = {groups[i] for i in fold}
        others = {groups[i] for other in folds if other is not fold for i in other}
        assert not fold_groups & others


def test_group_kfold_requires_two_groups():
    with pytest.raises(ValueError):
        group_kfold(["only"] * 5, 3, seed=0)


def test_grouped_split_keeps_experiments_on_one_side():
    examples = [TrainingExample(vector=[0.0], labels={"A": 1}, metadata={"experiment_id": f"EXP-{i // 5}"}) for i in range(40)]
    train, val = grouped_split(examples, example_group, 0.25, seed=3)
    assert train and val and len(train) + len(val) == 40
    assert not {example_group(e) for e in train} & {example_group(e) for e in val}


def test_f1_is_zero_not_missing_for_a_never_predicted_class():
    assert scores(0, 0, 5, 10)["f1"] == 0.0
    assert scores(0, 0, 0, 10)["f1"] is None


def test_positive_vs_control_semantics():
    def sample(kind, expected=None):
        return LabeledSession(session={"events": []}, trial_kind=kind, expected=expected, group="g", provenance="synthetic", vector=[0.0] * 15)

    samples = [sample("attack", "A"), sample("attack", "B"), sample("control"), sample("control")]
    # The B attack also triggered A: that is "unexpected", NOT an A false positive.
    predictions = [{"A"}, {"A", "B"}, set(), {"A"}]
    result = evaluate_predictions(samples, predictions, {"A", "B"})
    assert result["per_class"]["A"]["fp"] == 1  # only the control counts
    assert result["per_class"]["A"]["tn"] == 1
    assert result["unexpected_detections_on_attacks"] == 1
    assert result["alert"]["fpr"] == 0.5


def test_labeled_from_experiments_skips_inconclusive_and_uses_experiment_groups():
    experiment = {"experiment_id": "EXP-1", "result": "TP", "trial_kind": "attack", "expected_detection": "BRUTE_FORCE", "session_ids": ["S1"]}
    sessions = [{"session_id": "S1", "events": []}, {"session_id": "S2", "events": []}]
    labeled = labeled_from_experiments([(experiment, sessions), ({**experiment, "result": "INCONCLUSIVE"}, sessions)])
    assert [(s.group, s.expected, s.session["session_id"]) for s in labeled] == [("EXP-1", "BRUTE_FORCE", "S1")]


@pytest.fixture(scope="module")
def report():
    return compare(synthetic_corpus(seed=3, attackers_per_archetype=3, sessions_per_attacker=2), folds=3, epochs=60, seed=5)


def test_compare_report_structure_and_honesty(report):
    assert set(report["engines"]) == set(ENGINES)
    assert report["synthetic_warning"] is True and report["provenance"] == ["synthetic"]
    assert report["leakage_check"]["groups_spanning_folds"] == 0
    assert "leakage_inflation" in report["leakage_check"]["naive_split"]
    for engine in ENGINES:
        data = report["engines"][engine]
        assert {"per_class", "macro_f1", "alert", "latency_ms"} <= set(data)
        assert data["alert"]["fpr"] is None or 0 <= data["alert"]["fpr"] <= 1


def test_schema2_gives_the_learned_policy_ics_heads(report):
    # Feature schema 2 added ICS/exploit/staging heads, so the learned policy now
    # recalls classes it previously scored 0 on.
    assert report["engines"]["ml_trained"]["per_class"]["ICS_WRITE"]["recall"] > 0.5
    assert report["engines"]["rules"]["per_class"]["ICS_WRITE"]["recall"] == 1.0
    assert report["engines"]["anomaly"]["macro_f1"] is not None  # zero-F1 classes still count
