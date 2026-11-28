"""Optional shared-secret API auth: open by default, enforced when configured."""

from fastapi.testclient import TestClient

from backend.app import config
from backend.app.elastic import store
from backend.app.main import app

client = TestClient(app)


async def fake_search(index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
    return []


def _set_key(monkeypatch, api_key: str | None):
    if api_key is None:
        monkeypatch.delenv("API_KEY", raising=False)
    else:
        monkeypatch.setenv("API_KEY", api_key)
    config.get_settings.cache_clear()


def teardown_function():
    config.get_settings.cache_clear()


def test_api_is_open_when_no_key_configured(monkeypatch):
    monkeypatch.setattr(store, "search", fake_search)
    _set_key(monkeypatch, None)
    assert client.get("/health").status_code == 200
    assert client.get("/detections").status_code == 200


def test_key_required_when_configured(monkeypatch):
    monkeypatch.setattr(store, "search", fake_search)
    _set_key(monkeypatch, "s3cret")
    # Health stays exempt for liveness checks.
    assert client.get("/health").status_code == 200
    # A protected route is rejected without the header, accepted with the right key.
    assert client.get("/detections").status_code == 401
    assert client.get("/detections", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/detections", headers={"X-API-Key": "nope"}).status_code == 401
