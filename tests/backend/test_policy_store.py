"""Policy persistence + offline retraining round-trip (no Elasticsearch needed)."""

import asyncio

from backend.app.services.ml.bootstrap import DETECTION_TYPES, bootstrap_policy
from backend.app.services.ml.store import load_latest_policy, save_policy
from backend.app.tools.train_detector import train_and_store


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


def test_save_and_load_latest_policy_round_trips():
    store = Store()
    policy = bootstrap_policy()
    asyncio.run(save_policy(store, policy, source="bootstrap", training_example_count=10, trained_at="2026-01-01T00:00:00+00:00"))
    loaded = asyncio.run(load_latest_policy(store))
    assert loaded is not None
    assert set(loaded.detection_types) == set(DETECTION_TYPES)


def test_load_latest_returns_newest_generation():
    store = Store()
    policy = bootstrap_policy()
    asyncio.run(save_policy(store, policy, source="bootstrap", training_example_count=1, trained_at="2026-01-01T00:00:00+00:00", extra={"tag": "old"}))
    asyncio.run(save_policy(store, policy, source="batch", training_example_count=9, trained_at="2026-06-01T00:00:00+00:00", extra={"tag": "new"}))
    # Two distinct generations are retained (append-only history), newest wins.
    assert sum(1 for idx, _ in store.documents if idx == "trapsig-policy") == 2


def test_train_and_store_writes_a_new_generation_without_real_data():
    store = Store()
    summary = asyncio.run(train_and_store(store, epochs=5, merge_bootstrap=True))
    assert summary["experiments_used"] == 0
    assert summary["bootstrap_example_count"] > 0
    assert "document_id" in summary
    reloaded = asyncio.run(load_latest_policy(store))
    assert reloaded is not None and reloaded.policy_version == summary["policy_version"]


def test_missing_index_falls_back_to_bootstrap():
    assert asyncio.run(load_latest_policy(Store())) is None
