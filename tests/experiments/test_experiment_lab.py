"""Experiment lab: statistics, arm comparison, duplication, archiving, datasets."""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from backend.app.elastic import store
from backend.app.main import app
from backend.app.services.experiment_lab import arm_summary, compare_arms, dataset_bundle, fisher_exact, wilson_interval

client = TestClient(app)


def test_fisher_exact_matches_reference_values():
    # scipy.stats.fisher_exact([[1, 9], [11, 3]]) documented two-sided p-value
    assert fisher_exact(1, 9, 11, 3) == pytest.approx(0.0027594561852200836, rel=1e-9)
    assert fisher_exact(5, 5, 5, 5) == pytest.approx(1.0)
    assert fisher_exact(0, 0, 3, 4) is None  # empty row: not testable


def test_wilson_interval_properties():
    low, high = wilson_interval(0, 10)
    assert low == 0.0 and high == pytest.approx(0.2775, abs=1e-3)
    low, high = wilson_interval(10, 10)
    assert high == 1.0 and low == pytest.approx(0.7225, abs=1e-3)
    assert wilson_interval(0, 0) is None


def record(result, condition="baseline", latency=None, scenario="ssh-bruteforce", detector="policy-fs1+rules-x"):
    return {
        "result": result,
        "condition": condition,
        "status": "completed",
        "scenario_id": scenario,
        "detector_ruleset_version": detector,
        "detection_latency_seconds": latency,
    }


def test_arm_summary_excludes_inconclusive_from_denominators():
    summary = arm_summary([record("TP", latency=3), record("FN"), record("INCONCLUSIVE"), record("TN")])
    assert summary["counts"]["INCONCLUSIVE"] == 1
    assert summary["metrics"]["recall"] == 0.5 and summary["detection_latency_median_seconds"] == 3


def test_compare_arms_detects_a_real_difference_and_flags_confounders():
    baseline = [record("TP")] * 1 + [record("FN")] * 9
    adaptive = [record("TP", "adaptive")] * 11 + [record("FN", "adaptive")] * 3
    result = compare_arms(baseline, adaptive, labels=("baseline", "adaptive"))
    assert result["tests"]["recall_fisher_p"] == pytest.approx(0.0027594561852200836, rel=1e-9)
    assert result["delta"]["recall"] > 0 and "higher" in result["conclusion"]
    confounded = compare_arms(baseline, [record("TP", "adaptive", detector="other")] * 3, labels=("baseline", "adaptive"))
    assert any("different detector versions" in w for w in confounded["warnings"])
    assert any("fewer than 5" in w for w in confounded["warnings"])
    null = compare_arms([record("TP"), record("FN")] * 3, [record("TP", "adaptive"), record("FN", "adaptive")] * 3)
    assert "insufficient evidence" in null["conclusion"]


def test_dataset_bundle_hashes_are_verifiable():
    experiment = {"experiment_id": "EXP-1", "ground_truth": {"run_id": "R"}, "trial_kind": "attack", "result": "TP", "_id": "EXP-1"}
    events = [
        {"@timestamp": "2026-01-01T00:00:01Z", "event": {"id": "b"}, "trapsig": {"schema_version": "2"}, "_id": "b"},
        {"@timestamp": "2026-01-01T00:00:00Z", "event": {"id": "a"}, "_id": "a"},
    ]
    bundle = dataset_bundle(experiment, events, [], [])
    assert [e["event"]["id"] for e in bundle["events"]] == ["a", "b"] and "_id" not in bundle["events"][0]
    digest = hashlib.sha256(json.dumps(bundle["events"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert bundle["manifest"]["sha256"]["events"] == digest
    assert bundle["manifest"]["counts"]["events"] == 2 and bundle["manifest"]["format"] == "trapsig-dataset/1"


class Memory:
    def __init__(self):
        self.docs = {}

    async def save(self, index, document_id, document, *, refresh="wait_for"):
        self.docs.setdefault(index, {})[document_id] = dict(document)
        return document

    async def get(self, index, document_id):
        doc = self.docs.get(index, {}).get(document_id)
        return {**doc, "_id": document_id} if doc else None

    async def search(self, index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
        return [{**d, "_id": k} for k, d in self.docs.get(index, {}).items()][:size]

    async def search_all(self, index, query=None, *, sort=None, page_size=500, missing_index_is_empty=False):
        return [{**d, "_id": k} for k, d in self.docs.get(index, {}).items()]


@pytest.fixture
def memory(monkeypatch):
    mem = Memory()
    for name in ("save", "get", "search", "search_all"):
        monkeypatch.setattr(store, name, getattr(mem, name))
    return mem


def test_create_records_design_duplicate_and_archive(memory):
    payload = {
        "name": "Adaptive SSH",
        "scenario_id": "ssh-bruteforce",
        "attacker_ip": "192.168.50.20",
        "target_ip": "192.168.50.10",
        "objective": "Measure brute-force recall under adaptive deception",
        "hypothesis": "Adaptive deception does not reduce recall",
        "condition": "adaptive-deception",
        "tags": ["ssh", "h1"],
        "configuration": {"adaptive_deception": True},
        "evaluation_batch_id": "B1",
    }
    created = client.post("/experiments", json=payload)
    assert created.status_code == 201, created.text
    original = created.json()
    assert original["condition"] == "adaptive-deception" and original["hypothesis"].startswith("Adaptive")
    copy = client.post(f"/experiments/{original['experiment_id']}/duplicate").json()
    assert copy["experiment_id"] != original["experiment_id"] and copy["duplicated_from"] == original["experiment_id"]
    assert copy["condition"] == "adaptive-deception" and copy["replicate"] == 2 and copy["status"] == "created"
    assert client.post(f"/experiments/{original['experiment_id']}/archive").json()["archived"] is True
    listed = {e["experiment_id"] for e in client.get("/experiments").json()}
    assert original["experiment_id"] not in listed and copy["experiment_id"] in listed
    assert original["experiment_id"] in {e["experiment_id"] for e in client.get("/experiments?include_archived=true").json()}
    assert client.post("/experiments", json={**payload, "condition": "bad condition!"}).status_code == 422
    assert client.post("/experiments", json={**payload, "configuration": {"x": "y" * 9000}}).status_code == 422


def test_lab_compare_endpoint_and_dataset_requires_completion(memory):
    for index, (result, condition) in enumerate([("TP", "baseline"), ("FN", "baseline"), ("TP", "adaptive"), ("TP", "adaptive")]):
        memory.docs.setdefault("trapsig-experiments", {})[f"EXP-{index}"] = {**record(result, condition), "experiment_id": f"EXP-{index}"}
    memory.docs["trapsig-experiments"]["EXP-9"] = {"experiment_id": "EXP-9", "status": "running", "condition": "adaptive"}
    response = client.get("/experiment-lab/compare?condition_a=baseline&condition_b=adaptive").json()
    assert response["arms"]["baseline"]["experiments"] == 2 and response["arms"]["adaptive"]["experiments"] == 2
    assert client.get("/experiment-lab/compare?condition_a=baseline&condition_b=nope").status_code == 404
    conditions = {c["condition"]: c for c in client.get("/experiment-lab/conditions").json()}
    assert conditions["adaptive"]["experiments"] == 3 and conditions["adaptive"]["completed"] == 2
    assert client.get("/experiments/EXP-9/dataset").status_code == 409
    bundle = client.get("/experiments/EXP-0/dataset").json()
    assert bundle["manifest"]["experiment_id"] == "EXP-0"
