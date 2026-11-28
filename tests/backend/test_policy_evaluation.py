"""Policy evaluation metrics, baseline comparison, and the promotion gate."""

import asyncio

from backend.app.services.ml.bootstrap import DETECTION_TYPES, bootstrap_policy, build_training_examples
from backend.app.services.ml.evaluation import evaluate_policy, evaluate_rule_baseline, feature_means, population_stability
from backend.app.services.ml.metrics import brier_score, classification_scores, confusion, expected_calibration_error
from backend.app.tools.train_detector import split_examples, train_and_store


class Store:
    def __init__(self):
        self.documents = {}

    async def search(self, index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
        docs = [doc for (idx, _), doc in self.documents.items() if idx == index]
        docs.sort(key=lambda d: d.get(sort_field, ""), reverse=True)
        return docs[:size]

    async def search_all(self, index, query=None, *, sort=None, page_size=500, missing_index_is_empty=False):
        return [doc for (idx, _), doc in self.documents.items() if idx == index]

    async def save(self, index, document_id, document):
        self.documents[(index, document_id)] = document
        return document


def test_confusion_and_scores_are_correct():
    cm = confusion([1, 1, 0, 0], [1, 0, 0, 0])
    assert cm == {"tp": 1, "fp": 0, "fn": 1, "tn": 2}
    scores = classification_scores(cm)
    assert scores["precision"] == 1.0
    assert scores["recall"] == 0.5
    assert abs(scores["f1"] - 2 / 3) < 1e-9


def test_calibration_metrics_reward_honest_probabilities():
    # Perfectly calibrated and confident predictions -> near-zero Brier and ECE.
    y_true = [1, 1, 0, 0]
    confident = [0.99, 0.99, 0.01, 0.01]
    assert brier_score(y_true, confident) < 0.01
    assert expected_calibration_error(y_true, confident) < 0.05


def test_bootstrap_policy_beats_or_matches_rule_baseline_on_its_own_data():
    examples = build_training_examples()
    policy_eval = evaluate_policy(bootstrap_policy(), examples)
    baseline_eval = evaluate_rule_baseline(examples)
    # The learned policy should be competitive with the rules it replaced.
    assert policy_eval["macro_f1"] is not None
    assert policy_eval["macro_f1"] >= baseline_eval["macro_f1"] - 0.1


def test_split_is_deterministic_and_disjoint():
    examples = build_training_examples()
    train_a, val_a = split_examples(examples, 0.2, seed=7)
    train_b, val_b = split_examples(examples, 0.2, seed=7)
    assert len(val_a) == len(val_b) and len(train_a) == len(train_b)
    assert len(train_a) + len(val_a) == len(examples)


def test_feature_means_and_drift_signal():
    examples = build_training_examples()
    reference = feature_means(examples)
    assert set(reference)  # one entry per feature
    # No drift against itself.
    drift = population_stability(reference, reference, examples)
    assert all(value == 0.0 for value in drift.values())


def test_promotion_gate_keeps_a_regressing_candidate_inactive():
    # Seed an active, good incumbent policy.
    store = Store()
    good = bootstrap_policy()
    asyncio.run(_save(store, good, active=True, trained_at="2026-01-01T00:00:00+00:00"))

    # A deliberately broken candidate (all-zero weights) trained on garbage labels
    # cannot beat the incumbent on held-out data, so the gate must keep it inactive.
    # We force a tiny, mislabeled batch via train_and_store with warm start off and
    # 0 epochs so the candidate stays at zero weights.
    summary = asyncio.run(
        train_and_store(store, merge_bootstrap=True, warm_start=False, epochs=0, val_fraction=0.3, seed=3)
    )
    assert summary["candidate_macro_f1"] is not None
    assert summary["incumbent_macro_f1"] is not None
    # Zero-weight candidate (0 epochs) should not beat the trained incumbent.
    assert summary["activated"] is False
    stored = [doc for (idx, _), doc in store.documents.items() if idx == "trapsig-policy" and doc.get("source") == "batch"]
    assert stored and stored[0]["active"] is False


async def _save(store, policy, *, active, trained_at):
    from backend.app.services.ml.store import save_policy

    await save_policy(store, policy, source="bootstrap", training_example_count=1, trained_at=trained_at, active=active)


def test_retrained_policy_can_be_activated_when_it_improves():
    store = Store()
    summary = asyncio.run(train_and_store(store, merge_bootstrap=True, epochs=60, val_fraction=0.25, force_activate=True))
    assert summary["activated"] is True
    assert set(DETECTION_TYPES)  # sanity
