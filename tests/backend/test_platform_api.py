"""v2 API surface: RBAC + audit, detection lab, sensors, personas, network."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app import config, security
from backend.app.api.sensors import aggregate, instance_status
from backend.app.elastic import store
from backend.app.main import app
from backend.app.services.network import correlate, summarize_flows

client = TestClient(app)


class MemoryStore:
    """Minimal in-memory stand-in for the ES store methods these routers use."""

    def __init__(self):
        self.docs: dict[str, dict[str, dict]] = {}

    async def save(self, index, document_id, document, *, refresh="wait_for"):
        self.docs.setdefault(index, {})[document_id] = {**document}
        return document

    async def get(self, index, document_id):
        doc = self.docs.get(index, {}).get(document_id)
        return {**doc, "_id": document_id} if doc else None

    async def search(self, index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
        docs = [{**d, "_id": k} for k, d in self.docs.get(index, {}).items()]
        if query and "term" in query:
            ((field, value),) = query["term"].items()
            docs = [d for d in docs if d.get(field) == value]
        return sorted(docs, key=lambda d: str(d.get(sort_field, "")), reverse=True)[:size]

    async def count(self, index, query=None, missing_index_is_empty=False):
        return len(self.docs.get(index, {}))

    async def aggregate(self, *args, **kwargs):
        return {"aggregations": {}}


@pytest.fixture
def memory(monkeypatch):
    mem = MemoryStore()
    for name in ("save", "get", "search", "count", "aggregate"):
        monkeypatch.setattr(store, name, getattr(mem, name))
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("API_KEYS", raising=False)
    config.get_settings.cache_clear()
    yield mem
    config.get_settings.cache_clear()


# ---- RBAC & audit ------------------------------------------------------------- #


def keys(monkeypatch):
    monkeypatch.setenv("API_KEYS", "viewer:v-key,analyst:a-key,admin:ad-key,sensor:s-key")


def test_roles_are_enforced_by_the_policy_table(memory, monkeypatch):
    keys(monkeypatch)
    assert client.get("/detections").status_code == 401
    assert client.get("/detections", headers={"X-API-Key": "v-key"}).status_code == 200
    # viewer cannot write; analyst can create (validation error proves authz passed)
    assert client.post("/experiments", json={}, headers={"X-API-Key": "v-key"}).status_code == 403
    assert client.post("/experiments", json={}, headers={"X-API-Key": "a-key"}).status_code == 422
    # admin-only: rule state, honeypot control
    rule_id = client.get("/detection/rules", headers={"X-API-Key": "v-key"}).json()[0]["id"]
    assert client.post(f"/detection/rules/{rule_id}/state", json={"enabled": False}, headers={"X-API-Key": "a-key"}).status_code == 403
    assert client.post(f"/detection/rules/{rule_id}/state", json={"enabled": False}, headers={"X-API-Key": "ad-key"}).status_code == 200
    # sensor key: heartbeat + posture only
    assert client.get("/adaptation/posture", headers={"X-API-Key": "s-key"}).status_code == 200
    assert client.get("/events", headers={"X-API-Key": "s-key"}).status_code == 403
    assert client.get("/audit", headers={"X-API-Key": "a-key"}).status_code == 403


def test_mutations_and_denials_are_audited(memory, monkeypatch):
    keys(monkeypatch)
    client.post("/experiments", json={}, headers={"X-API-Key": "v-key"})
    client.get("/events", headers={"X-API-Key": "bad"})
    rule_id = client.get("/detection/rules", headers={"X-API-Key": "v-key"}).json()[0]["id"]
    client.post(f"/detection/rules/{rule_id}/state", json={"enabled": True}, headers={"X-API-Key": "ad-key"})
    records = list(memory.docs[security.AUDIT_INDEX].values())
    outcomes = {(r["method"], r["outcome"], r["role"]) for r in records}
    assert ("POST", "forbidden", "viewer") in outcomes
    assert ("GET", "unauthenticated", None) in outcomes
    assert ("POST", "ok", "admin") in outcomes
    assert all("ad-key" not in str(r) for r in records), "keys must never be logged"


def test_legacy_single_key_is_admin_and_open_mode_still_works(memory, monkeypatch):
    assert client.get("/detections").status_code == 200  # open lab
    monkeypatch.setenv("API_KEY", "legacy")
    assert security.authenticate("legacy").role == "admin"
    assert security.authenticate("wrong") is None


# ---- detection lab -------------------------------------------------------------- #


def test_rule_listing_self_test_and_ad_hoc_test(memory):
    rules = client.get("/detection/rules").json()
    assert any(r["name"] == "password-guessing" and r["kind"] == "correlation" for r in rules)
    report = client.get("/detection/rules/self-test").json()
    assert report["cases"] > 50 and report["failures"] == []
    fired = client.post(
        "/detection/rules/password-guessing/test",
        json={"events": [{"event": {"category": "authentication", "outcome": "failure"}, "service": {"name": "cowrie"}}] * 5},
    ).json()
    assert fired["fired"] and len(fired["evidence_event_ids"]) == 5
    assert client.post("/detection/rules/password-guessing/test", json={"events": [{"event": {"category": "web"}}]}).json()["fired"] is False


def test_rule_state_override_is_persisted_and_reported(memory):
    rule = client.get("/detection/rules/shell-command").json()
    assert rule["enabled"] is True and rule["test_results"]
    client.post(f"/detection/rules/{rule['id']}/state", json={"enabled": False, "reason": "noisy in lab"})
    after = next(r for r in client.get("/detection/rules").json() if r["name"] == "shell-command")
    assert after["enabled"] is False and after["override"] is True


def test_engines_and_attack_coverage(memory):
    engines = client.get("/detection/engines").json()
    assert engines["rules"]["count"] > 20 and engines["ml"]["confidence_calibrated"] is False
    coverage = client.get("/detection/attack").json()
    t1110 = next(t for t in coverage["techniques"] if t["id"] == "T1110.001")
    assert "password-guessing" in t1110["rules"]


def test_logged_comparison_requires_groups(memory, monkeypatch):
    async def none():
        return []

    monkeypatch.setattr("backend.app.api.detection.logged_samples", none)
    assert client.post("/detection/comparisons", json={"source": "logged"}).status_code == 409


# ---- sensors ---------------------------------------------------------------------- #


def beat(sensor="pi-01", persona="industrial-plc", listening=True):
    return {
        "sensor_id": sensor,
        "hostname": "trapsig-pi",
        "persona": {"id": persona, "name": "PLC", "version": 1, "content_sha256": "abc", "enabled": True},
        "services": [{"name": "modbus", "plugin": "modbus", "transport": "tcp", "port": 5020, "public_port": 502, "listening": listening, "events": 4}],
    }


def test_heartbeats_aggregate_into_sensor_health(memory):
    assert client.post("/sensors/heartbeat", json=beat()).status_code == 202
    assert client.post("/sensors/heartbeat", json=beat(persona="nas", listening=False)).status_code == 202
    sensors = client.get("/sensors").json()
    assert len(sensors) == 1 and sensors[0]["status"] == "degraded"
    assert sensors[0]["services_total"] == 2 and sensors[0]["services_listening"] == 1
    assert client.post("/sensors/heartbeat", json={**beat(), "sensor_id": "bad id!"}).status_code == 422


def test_instance_goes_offline_without_heartbeats():
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    assert instance_status({"received_at": old, "services": []}) == "offline"
    assert aggregate([{"sensor_id": "x", "received_at": old, "persona": {}, "services": []}])[0]["status"] == "offline"


# ---- personas --------------------------------------------------------------------- #


def test_persona_catalog_versioning_and_drift(memory):
    listing = {p["id"]: p for p in client.get("/personas").json()}
    assert {"industrial-plc", "nas", "smart-camera"} <= set(listing)
    assert listing["industrial-plc"]["origin"] == "seed"
    detail = client.get("/personas/industrial-plc").json()
    definition = {**detail["definition"], "firmware": "4.3.0"}
    saved = client.put("/personas/industrial-plc", json={"definition": definition, "note": "firmware bump"}).json()
    assert saved["version"] == 2
    effective = client.get("/personas/industrial-plc/effective").json()
    assert effective["origin"] == "stored" and effective["definition"]["firmware"] == "4.3.0"
    client.post("/sensors/heartbeat", json=beat())  # running sha "abc" != effective
    drift = client.get("/personas/industrial-plc").json()["deployments"][0]
    assert drift["in_sync"] is False
    disabled = client.post("/personas/industrial-plc/state", json={"enabled": False}).json()
    assert disabled["version"] == 3 and disabled["enabled"] is False


def test_invalid_persona_is_rejected_with_validator_message(memory):
    bad = {"id": "industrial-plc", "name": "x", "device_type": "generic", "services": [{"plugin": "modbus", "port": 502}]}
    response = client.put("/personas/industrial-plc", json={"definition": bad})
    assert response.status_code == 422 and "privileged" in response.json()["detail"]
    assert client.post("/personas/validate", json={"definition": {**bad, "services": [{"plugin": "modbus", "port": 5020}]}}).json()["valid"]
    assert client.get("/personas/plugins").json()[0]["name"]


# ---- network ------------------------------------------------------------------------ #


def flow(cid, src="192.168.50.20", port=502, state="SF", dataset="zeek.conn"):
    return {
        "network": {"community_id": cid},
        "source": {"ip": src},
        "destination": {"port": port},
        "event": {"dataset": dataset},
        "zeek": {"uid": "C1", "conn_state": state, "orig_bytes": 10, "resp_bytes": 20},
    }


def test_community_id_correlation_and_network_only_scans():
    events = [{"event": {"id": "e1"}, "network": {"community_id": "1:a"}}, {"event": {"id": "e2"}, "network": {"community_id": "1:b"}}]
    flows = [flow("1:a")] + [flow(f"1:scan{p}", src="192.168.50.99", port=p, state="S0") for p in range(20, 40)]
    result = correlate(events, flows)
    assert result["events_matched"] == 1 and result["coverage"] == 0.5
    assert result["pairs"][0]["event_ids"] == ["e1"] and result["pairs"][0]["conn_state"] == "SF"
    assert result["network_only"]["likely_port_scanners"] == ["192.168.50.99"]
    assert summarize_flows([])["sources"] == []


# ---- RL hardening API ------------------------------------------------------------ #


def test_adaptation_endpoints_expose_decisions_learning_and_policy(memory, monkeypatch):
    import asyncio
    from datetime import datetime, timedelta, timezone

    from backend.app.services import hardening as rl

    t0 = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)
    detection = {"detection_id": "D1", "source_ip": "192.168.50.20", "type": "ICS_WRITE", "severity": "critical", "timestamp": t0.isoformat()}

    async def no_events(*args, **kwargs):
        return []

    monkeypatch.setattr(store, "search_all", no_events)  # attacker went quiet: no harm, no intel
    agent = rl.HardeningAgent(store)
    asyncio.run(agent.step([detection], now=t0))
    posture = client.get("/adaptation/posture").json()
    assert posture[0]["source_ip"] == "192.168.50.20" and posture[0]["action"] != "observe"  # safety floor
    asyncio.run(agent.step([], now=t0 + timedelta(seconds=rl.config()["window_seconds"] + 1)))
    decisions = client.get("/adaptation/decisions").json()
    assert decisions[0]["context"] == "ics_impact|it|new" and decisions[0]["surface"] == "it" and decisions[0]["outcome"]["reward"] == 0.0
    learned = client.get("/adaptation/agent").json()
    assert learned["evaluated_decisions"] == 1 and len(learned["table"]) == 80 and len(learned["contexts"]) == 16
    assert {row["action"] for row in learned["table"] if row["outcomes"]} == {decisions[0]["action"]}
    policy = client.get("/adaptation/policy").json()
    assert "Thompson" in policy["kind"] and any("ics_impact" in rule for rule in policy["safety"])
