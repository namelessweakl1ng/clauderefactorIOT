"""Fleet assignment validation, the native sensor agent's hot reload, and shipping."""

import asyncio
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

import agent  # noqa: E402

from backend.app.services import fleet  # noqa: E402
from backend.app.services import personas as persona_service  # noqa: E402


def _free():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


# ---- fleet validation ------------------------------------------------------------ #


def available():
    return persona_service.seeds()


def test_default_fleet_layout_is_valid_for_four_devices():
    seeds = fleet.seeds()
    assert set(seeds) == {"pi-ot", "host-home", "host-office", "host-server"}
    for sensor in seeds.values():
        fleet.validate(sensor, available())  # raises on any port conflict
    assigned = {p["persona_id"] for s in seeds.values() for p in s["personas"]}
    assert assigned == set(available())  # every persona is deployed somewhere


@pytest.mark.parametrize(
    "personas,message",
    [
        ([{"persona_id": "ops-workstation"}, {"persona_id": "hmi-panel"}], "port conflict"),  # both VNC 5900
        ([{"persona_id": "ops-workstation"}, {"persona_id": "hmi-panel", "bind_ip": "192.168.50.40"}], "port conflict"),  # wildcard vs alias
        ([{"persona_id": "nope"}], "unknown persona"),
        ([{"persona_id": "nas"}, {"persona_id": "nas"}], "assigned twice"),
        ([{"persona_id": "nas", "bind_ip": "127.0.0.1"}], "loopback"),
        ([{"persona_id": "nas", "bind_ip": "not-an-ip"}], "not an IP"),
    ],
)
def test_invalid_assignments_are_rejected(personas, message):
    with pytest.raises(fleet.FleetError, match=message):
        fleet.validate({"personas": personas}, available())


def test_separate_aliases_or_disabled_personas_do_not_conflict():
    fleet.validate(
        {"personas": [{"persona_id": "ops-workstation", "bind_ip": "192.168.50.41"}, {"persona_id": "hmi-panel", "bind_ip": "192.168.50.42"}]}, available()
    )
    fleet.validate({"personas": [{"persona_id": "ops-workstation"}, {"persona_id": "hmi-panel", "enabled": False}]}, available())


# ---- agent: hot reload on real sockets -------------------------------------------- #


def definition(pid, port):
    return {"id": pid, "name": pid, "device_type": "generic", "services": [{"plugin": "ftp", "port": 2121, "public_port": port}]}


def assignment(fingerprint, *entries):
    return {
        "sensor_id": "test",
        "fingerprint": fingerprint,
        "personas": [{"persona_id": pid, "bind_ip": "127.0.0.1"} for pid, _ in entries],
        "definitions": {pid: {"definition": definition(pid, port)} for pid, port in entries},
    }


def connects(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
            return client.recv(64).startswith(b"220")
    except OSError:
        return False


def test_agent_applies_and_hot_reloads_assignments(tmp_path, monkeypatch):
    monkeypatch.delenv("BACKEND_URL", raising=False)
    config = {"data_dir": tmp_path, "sensor_ip": "192.168.50.31", "sensor_id": "test"}
    first, second = _free(), _free()
    personas = agent.PersonaSet(config)
    personas.apply(assignment("v1", ("dev-a", first)))
    assert connects(first)
    personas.apply(assignment("v1", ("dev-a", first)))  # same fingerprint: no restart
    assert len(personas.running) == 1
    personas.apply(assignment("v2", ("dev-b", second)))
    assert connects(second) and not connects(first)  # old persona stopped, port released
    events = (tmp_path / "logs" / "dev-b.jsonl").read_text().splitlines()
    assert json.loads(events[0])["persona"]["id"] == "dev-b"


def test_blocked_port_does_not_stop_other_services(tmp_path):
    from common.persona import parse_persona
    from common.runtime import serve_persona_native, stop_servers

    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen()
    busy, free = taken.getsockname()[1], _free()
    doc = {
        "id": "two",
        "name": "two",
        "device_type": "generic",
        "services": [{"plugin": "ftp", "port": 2121, "public_port": busy}, {"plugin": "rtsp", "port": 8554, "public_port": free}],
    }
    threads, _, failures = serve_persona_native(parse_persona(doc), log_path=str(tmp_path / "x.jsonl"), sensor_ip=None, host="127.0.0.1")
    try:
        assert list(failures) == ["ftp"] and len(threads) == 1
    finally:
        stop_servers(threads)
        taken.close()


# ---- agent: shipping ------------------------------------------------------------------ #


class Collector(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Collector.received.append((self.headers["Authorization"], self.headers["Content-Type"], body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_shipper_sends_ndjson_with_offsets_partial_lines_and_rotation(tmp_path):
    server = HTTPServer(("127.0.0.1", 0), Collector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Collector.received = []
    config = {
        "data_dir": tmp_path,
        "sensor_id": "pi-ot",
        "sensor_ip": "192.168.50.10",
        "ingest_url": f"http://127.0.0.1:{server.server_port}",
        "ingest_user": "trapsig",
        "ingest_password": "pw",
        "backend_url": "http://x",
    }
    logs = tmp_path / "logs"
    logs.mkdir()
    log = logs / "plc.jsonl"
    log.write_text('{"event_id": "1"}\n{"event_id": "2"}\n{"event_id": "3"', encoding="utf-8")  # last line still being written
    shipper = agent.Shipper(config, threading.Event())
    try:
        assert shipper.ship_once() == 2
        auth, ctype, body = Collector.received[0]
        records = [json.loads(line) for line in body.decode().splitlines()]
        assert ctype == "application/x-ndjson" and auth.startswith("Basic ")
        assert [json.loads(r["message"])["event_id"] for r in records] == ["1", "2"]
        assert records[0]["fields"] == {"sensor_id": "pi-ot", "sensor_ip": "192.168.50.10"}
        assert shipper.ship_once() == 0  # nothing new; partial line held back
        with log.open("a", encoding="utf-8") as stream:
            stream.write("}\n")
        assert shipper.ship_once() == 1 and json.loads(agent.Shipper(config, threading.Event()).offsets_path.read_text())[str(log)] == log.stat().st_size
        log.write_text('{"event_id": "9"}\n', encoding="utf-8")  # rotated: smaller than offset
        assert shipper.ship_once() == 1
    finally:
        server.shutdown()


# ---- fleet API ------------------------------------------------------------------------ #


def test_fleet_api_assignment_and_validation(monkeypatch):
    from fastapi.testclient import TestClient

    from backend.app.elastic import store
    from backend.app.main import app

    docs: dict = {}

    async def search(index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
        return [{**d, "_id": k} for k, d in docs.get(index, {}).items()]

    async def save(index, document_id, document, *, refresh="wait_for"):
        docs.setdefault(index, {})[document_id] = document
        return document

    monkeypatch.setattr(store, "search", search)
    monkeypatch.setattr(store, "save", save)
    client = TestClient(app)
    listing = {s["sensor_id"]: s for s in client.get("/fleet").json()}
    assert listing["pi-ot"]["origin"] == "seed" and listing["pi-ot"]["personas"][0]["status"] == "not running"
    got = client.get("/fleet/pi-ot/assignment").json()
    assert set(got["definitions"]) == {p["persona_id"] for p in got["personas"]} and got["fingerprint"]
    bad = client.put("/fleet/host-server", json={"personas": [{"persona_id": "ops-workstation"}, {"persona_id": "hmi-panel"}]})
    assert bad.status_code == 422 and "port conflict" in bad.json()["detail"]
    good = client.put("/fleet/host-server", json={"personas": [{"persona_id": "edge-server"}, {"persona_id": "ops-workstation"}]})
    assert good.status_code == 200 and good.json()["version"] == 1
    assert client.get("/fleet/host-server/assignment").json()["fingerprint"] != got["fingerprint"]
    assert client.get("/fleet/unknown/assignment").status_code == 404
    assert asyncio.run(fleet.assignments(store))["host-server"]["origin"] == "stored"
