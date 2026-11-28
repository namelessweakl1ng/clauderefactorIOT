"""Schema v2: Logstash/reference-normalizer parity, Zeek routing, sensor→detection."""

import json
import re
import socket
import struct
import sys
from pathlib import Path

from backend.app.services.detector import detect
from backend.app.services.normalizer import V2_NAMESPACES, V2_TOP_LEVEL, normalize
from backend.app.services.sessionizer import reconstruct_sessions

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "sensor/honeypots"))

from common.persona import parse_persona  # noqa: E402
from common.runtime import Telemetry, serve_connection  # noqa: E402

PIPELINE = (ROOT / "elk/logstash/pipelines/20-json-honeypots.conf").read_text()


def logstash_whitelist() -> dict[str, tuple[str, ...]]:
    block = PIPELINE[PIPELINE.index("spec = {") : PIPELINE.index("spec.each")]
    return {ns: tuple(keys.split()) for ns, keys in re.findall(r'"(\w+)" => %w\[([^\]]*)\]', block)}


def test_logstash_and_reference_normalizer_whitelists_are_identical():
    assert logstash_whitelist() == V2_NAMESPACES
    for source in V2_TOP_LEVEL:
        assert f'"{source}" =>' in PIPELINE


def test_logstash_v2_transport_and_schema_version_contract():
    validation = (ROOT / "elk/logstash/pipelines/90-validation.conf").read_text()
    assert "%w[tcp udp].include?(transport)" in PIPELINE
    assert 'schema == "2" ? "2" : "1"' in validation
    assert "invalid_network_transport" in validation
    assert '[fields][log_family] != "zeek"' in validation  # zeek has its own checks


def test_zeek_pipeline_is_isolated_idempotent_and_routed():
    zeek = (ROOT / "elk/logstash/pipelines/30-zeek.conf").read_text()
    output = (ROOT / "elk/logstash/pipelines/99-output.conf").read_text()
    assert 'fingerprint { source => "message" target => "[event][id]" method => "SHA256" }' in zeek
    assert '"[network][community_id]"' in zeek and "community-id" in zeek.lower()
    assert 'index => "trapsig-network-%{+YYYY.MM.dd}"' in output
    for conf in ("10-cowrie.conf", "20-json-honeypots.conf"):
        assert '[fields][log_family] != "zeek"' in (ROOT / "elk/logstash/pipelines" / conf).read_text()
    filebeat = (ROOT / "sensor/filebeat/filebeat.yml").read_text()
    assert filebeat.count("log_family: zeek") == 4


def test_zeek_profile_is_opt_in_passive_and_excludes_management_traffic():
    import yaml

    compose = yaml.safe_load((ROOT / "sensor/docker-compose.yml").read_text())
    zeek = compose["services"]["zeek"]
    assert zeek["profiles"] == ["netmon"] and zeek["cap_drop"] == ["ALL"]
    assert set(zeek["cap_add"]) == {"NET_RAW", "NET_ADMIN"} and zeek["read_only"] is True
    bpf = " ".join(zeek["command"])
    for port in ("22", "5044", "41641", "8000"):
        assert f"not port {port}" in bpf
    for name, service in compose["services"].items():
        if name.startswith("persona-"):
            assert service["profiles"] == ["personas"] and service["read_only"] is True and service["cap_drop"] == ["ALL"]
            container_ports = [int(p.split(":")[1].split("/")[0]) for p in service["ports"]]
            assert all(port >= 1024 for port in container_ports), f"{name} binds a privileged container port"


def _run_plugin_conversation(tmp_path, persona_doc, payload: bytes):
    persona = parse_persona(persona_doc)
    telemetry = Telemetry(persona, str(tmp_path / "events.jsonl"), "192.168.50.10")
    binding = persona.bindings()[0]
    left, right = socket.socketpair()
    try:
        left.sendall(payload)
        left.shutdown(socket.SHUT_WR)
        serve_connection(right, ("192.168.50.20", 40500), binding, telemetry)
    finally:
        left.close()
        right.close()
    return [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]


def test_persona_events_flow_through_normalizer_sessions_and_rules(tmp_path):
    doc = {
        "id": "plc-e2e",
        "name": "PLC",
        "device_type": "industrial_plc",
        "vendor": "Halvern",
        "model": "HX",
        "firmware": "1",
        "services": [{"plugin": "modbus", "port": 5020, "public_port": 502}],
    }
    frames = b"".join(
        struct.pack("!HHHB", n, 0, len(pdu) + 1, 1) + pdu
        for n, pdu in enumerate([bytes([0x2B, 0x0E, 0x01, 0x00]), struct.pack("!BHH", 6, 0, 1), struct.pack("!BHH", 3, 0, 2)], start=1)
    )
    raw_events = _run_plugin_conversation(tmp_path, doc, frames)
    assert [e["modbus"]["function_code"] for e in raw_events] == [43, 6, 3]
    normalized = []
    for raw in raw_events:
        normalized.append(normalize({**raw, "destination_ip": "192.168.50.10"}, raw["honeypot_type"], raw["honeypot_id"], "pi-01"))
    first = normalized[0]
    assert first["trapsig"]["schema_version"] == "2" and first["network"]["transport"] == "tcp"
    assert first["persona"]["id"] == "plc-e2e" and first["network"]["community_id"].startswith("1:")
    assert first["destination"]["port"] == 502  # published port, the tuple Zeek sees
    assert first["trapsig"]["connection_id"] == normalized[-1]["trapsig"]["connection_id"]
    session = reconstruct_sessions(normalized)[0]
    assert session["personas"] == ["plc-e2e"] and session["connection_count"] == 1 and len(session["community_ids"]) == 1
    kinds = {d["type"]: d for d in detect(session)}
    assert {"ICS_RECONNAISSANCE", "ICS_WRITE"} <= set(kinds)
    assert kinds["ICS_WRITE"]["evidence_event_ids"] == [normalized[1]["event"]["id"]]


def test_reference_normalizer_drops_unlisted_namespace_keys():
    raw = {
        "schema_version": 2,
        "timestamp": "2026-01-01T00:00:00Z",
        "event_id": "x",
        "source_ip": "192.168.50.20",
        "destination_ip": "192.168.50.10",
        "protocol": "coap",
        "transport": "udp",
        "service": "coap",
        "coap": {"method": "GET", "attacker_controlled_key": "boom"},
        "evil_top_level": {"a": 1},
    }
    event = normalize(raw, "coap", "x-coap", "pi-01")
    assert event["coap"] == {"method": "GET"} and "evil_top_level" not in event
    assert event["network"]["transport"] == "udp"
    legacy = normalize({**raw, "schema_version": None, "transport": "sctp"}, "coap", "x-coap", "pi-01")
    assert legacy["trapsig"]["schema_version"] == "1" and "coap" not in legacy and legacy["network"]["transport"] == "tcp"
