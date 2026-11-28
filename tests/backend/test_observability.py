"""Metrics exposition, health probes, and structured logging."""

import json
import logging

from fastapi.testclient import TestClient

from backend.app.elastic import store
from backend.app.logging_config import JsonFormatter
from backend.app.main import app

client = TestClient(app)


async def fake_count(index, query=None, missing_index_is_empty=False):
    return {"trapsig-events-*": 42, "trapsig-detections": 7}.get(index, 0)


async def fake_search(index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
    return []


async def healthy():
    return {"status": "green"}


async def unavailable():
    raise RuntimeError("down")


def test_liveness_is_always_ok():
    assert client.get("/health/live").json()["status"] == "alive"


def test_readiness_reflects_elasticsearch(monkeypatch):
    monkeypatch.setattr(store, "health", healthy)
    assert client.get("/health/ready").status_code == 200
    monkeypatch.setattr(store, "health", unavailable)
    response = client.get("/health/ready")
    assert response.status_code == 503 and response.json()["status"] == "not-ready"


def test_metrics_emits_prometheus_text(monkeypatch):
    monkeypatch.setattr(store, "count", fake_count)
    monkeypatch.setattr(store, "search", fake_search)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "trapsig_events_total 42" in body
    assert "# TYPE trapsig_detections_total gauge" in body


def test_json_log_formatter_produces_valid_json():
    record = logging.LogRecord("trapsig", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    parsed = json.loads(JsonFormatter().format(record))
    assert parsed["level"] == "INFO" and parsed["message"] == "hello world" and parsed["logger"] == "trapsig"
