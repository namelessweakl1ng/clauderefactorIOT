"""Persona runtime: bounds, reflection guard, envelopes, and a real-socket run."""

import json
import socket
import struct
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

from common.heartbeat import build_payload  # noqa: E402
from common.persona import parse_persona  # noqa: E402
from common.plugin import Conversation, ProtocolPlugin, Reply  # noqa: E402
from common.runtime import (  # noqa: E402
    AMPLIFICATION_FACTOR,
    ReflectionGuard,
    ServiceBinding,
    Telemetry,
    TokenBucket,
    handle_datagram,
    serve_connection,
    serve_persona,
)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def persona_doc(**services):
    return {
        "id": "rt-test",
        "name": "Runtime Test",
        "device_type": "generic",
        "vendor": "Acme",
        "model": "RT",
        "firmware": "1",
        "credentials": {"accept": [["admin", "admin"]]},
        "interaction": {"max_messages": 5, "max_seconds": 10},
        "services": list(services.values()),
    }


def read_events(path):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if path.exists() and path.read_text().strip():
            break
        time.sleep(0.05)
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_token_bucket_and_guard_limits():
    bucket = TokenBucket(rate=1, burst=2)
    assert bucket.take(0) and bucket.take(0) and not bucket.take(0)
    assert bucket.take(1.0)
    guard = ReflectionGuard(per_source_rate=0, per_source_burst=3, global_rate=1000)
    assert [guard.admit("1.1.1.1", now=0) for _ in range(4)] == [True, True, True, False]
    assert guard.admit("2.2.2.2", now=0)
    assert ReflectionGuard.size_ok(b"x" * 10, b"y" * 10 * AMPLIFICATION_FACTOR)
    assert not ReflectionGuard.size_ok(b"x" * 10, b"y" * (10 * AMPLIFICATION_FACTOR + 1))


class _Echo(ProtocolPlugin):
    name, protocol, default_port, transport = "echo-test", "echo", 7777, "udp"

    def datagram(self, data, client):
        return Reply(data * 50, [{"action": "echo"}])


class _FakeSock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, client):
        self.sent.append(data)


def _telemetry(tmp_path):
    persona = parse_persona(persona_doc(a={"plugin": "dns", "port": 5353}))
    return Telemetry(persona, str(tmp_path / "events.jsonl"), "192.168.50.10")


def test_oversized_udp_reply_is_suppressed_and_logged(tmp_path):
    telemetry = _telemetry(tmp_path)
    binding = ServiceBinding(_Echo(telemetry.persona.context()), "echo", 7777, 7777, 5, 10)
    sock = _FakeSock()
    assert handle_datagram(b"hi", sock, ("192.168.50.20", 5000), binding, telemetry, ReflectionGuard()) is False
    assert sock.sent == []
    event = json.loads((tmp_path / "events.jsonl").read_text())
    assert event["reply_suppressed"] == "amplification_cap" and event["transport"] == "udp"


class _Chatty(ProtocolPlugin):
    name, protocol, default_port = "chatty-test", "chat", 7778

    def conversation(self, client):
        plugin = self

        class C(Conversation):
            def handle(self, message):
                if message.startswith(b"boom"):
                    raise RuntimeError("parser bug")
                return Reply(b"ok\n", [{"action": "line", "chat": {"text": message.decode().strip()}}])

        return C(plugin, client)


def test_message_bound_sequence_and_parser_errors(tmp_path):
    telemetry = _telemetry(tmp_path)
    binding = ServiceBinding(_Chatty(telemetry.persona.context()), "chat", 7778, 7778, max_messages=3, max_seconds=5)
    left, right = socket.socketpair()
    try:
        left.sendall(b"a\nb\nc\nd\n")
        assert serve_connection(right, ("192.168.50.20", 1), binding, telemetry) == 3
    finally:
        left.close()
        right.close()
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert [e["sequence"] for e in events] == [1, 2, 3, 4]
    assert events[-1]["action"] == "message_limit"
    assert len({e["connection_id"] for e in events}) == 1
    assert events[0]["chat"] == {"text": "a"}

    left, right = socket.socketpair()
    try:
        left.sendall(b"boom\n")
        serve_connection(right, ("192.168.50.20", 2), binding, telemetry)
    finally:
        left.close()
        right.close()
    last = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[-1])
    assert last["action"] == "parser_error" and last["outcome"] == "failure"


def test_envelope_v2_fields_and_credential_redaction(tmp_path):
    doc = persona_doc(a={"plugin": "ftp", "port": 2121, "public_port": 21})
    doc["logging"] = {"credentials": "redact", "payload_bytes": 0}
    persona = parse_persona(doc)
    telemetry = Telemetry(persona, str(tmp_path / "e.jsonl"), "192.168.50.10")
    binding = persona.bindings()[0]
    event = telemetry.envelope(
        binding,
        ("192.168.50.20", 41000),
        {"category": "authentication", "action": "login_attempt", "outcome": "failure", "authentication": {"username": "root", "password": "hunter2"}},
        connection_id="c1",
        sequence=1,
        payload=b"PASS hunter2",
    )
    assert event["schema_version"] == 2 and event["destination_port"] == 21 and event["transport"] == "tcp"
    assert event["persona"]["id"] == "rt-test" and event["community_id"].startswith("1:")
    assert event["authentication"]["password"] == "<redacted>" and "payload_excerpt" not in event
    assert event["honeypot_id"] == "rt-test-ftp"


def test_real_sockets_end_to_end(tmp_path):
    tcp_port, udp_port, ftp_port = free_port(), free_port(socket.SOCK_DGRAM), free_port()
    persona = parse_persona(
        persona_doc(
            modbus={"plugin": "modbus", "port": tcp_port, "options": {"holding_registers": [5, 6]}},
            coap={"plugin": "coap", "port": udp_port, "options": {"resources": {"/t": "1"}}},
            ftp={"plugin": "ftp", "name": "ftp", "port": ftp_port},
        )
    )
    log = tmp_path / "persona.jsonl"
    threads, telemetry = serve_persona(persona, log_path=str(log), sensor_ip="192.168.50.10", host="127.0.0.1")
    with socket.create_connection(("127.0.0.1", tcp_port), timeout=3) as client:
        client.sendall(struct.pack("!HHHB", 1, 0, 6, 1) + struct.pack("!BHH", 3, 0, 2))
        assert client.recv(64).endswith(struct.pack("!HH", 5, 6))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        udp.sendto(bytes([0x41, 1, 0, 9, 0xAA, 0xB1]) + b"t", ("127.0.0.1", udp_port))
        data, _ = udp.recvfrom(512)
        assert data[1] == 0x45  # 2.05 Content
    with socket.create_connection(("127.0.0.1", ftp_port), timeout=3) as client:
        assert client.recv(128).startswith(b"220")
        client.sendall(b"USER admin\r\nPASS admin\r\nQUIT\r\n")
        received = b""
        while b"221" not in received:
            chunk = client.recv(256)
            if not chunk:
                break
            received += chunk
        assert b"230" in received
    time.sleep(0.2)
    events = read_events(log)
    services = {e["service"] for e in events}
    assert {"modbus", "coap", "ftp"} <= services
    assert all(e["schema_version"] == 2 and e["persona"]["id"] == "rt-test" for e in events)
    auth = next(e for e in events if e.get("category") == "authentication")
    assert auth["outcome"] == "success" and auth["authentication"]["username"] == "admin"
    payload = build_payload(persona, "file", telemetry, threads, time.monotonic() - 5)
    by_name = {s["name"]: s for s in payload["services"]}
    assert by_name["modbus"]["listening"] and by_name["coap"]["listening"] and by_name["ftp"]["events"] >= 3
    assert payload["persona"]["id"] == "rt-test" and payload["schema_version"] == 2


def test_legacy_adapter_matches_direct_persona(tmp_path):
    from camera.persona import CameraPersona

    persona = parse_persona(persona_doc(cam={"plugin": "asterview-camera-http", "port": 8081}))
    binding = persona.bindings()[0]
    request = b"GET /login HTTP/1.1\r\nHost: cam\r\n\r\n"
    direct = CameraPersona()
    via_plugin = binding.plugin.conversation(("192.168.50.20", 1)).handle(request)
    expected = direct.response(direct.parse(request))
    strip = lambda b: b"\r\n".join(line for line in b.split(b"\r\n") if not line.lower().startswith((b"date:", b"set-cookie:")))  # noqa: E731
    assert strip(via_plugin.data) == strip(expected)
    assert via_plugin.events[0]["url"] == {"path": "/login"}


@pytest.mark.parametrize("bad", [b"\xff" * 300, b"", b"\x00\x00\x00\x00\x00\x06\x01\x03"])
def test_runtime_survives_garbage_on_every_tcp_plugin(tmp_path, bad):
    from common.plugin import REGISTRY

    telemetry = _telemetry(tmp_path)
    for name, cls in REGISTRY.items():
        if cls.transport != "tcp":
            continue
        plugin = cls(telemetry.persona.context(), {})
        binding = ServiceBinding(plugin, name, 9999, 9999, 4, 2)
        left, right = socket.socketpair()
        try:
            left.sendall(bad)
            left.shutdown(socket.SHUT_WR)
            serve_connection(right, ("192.168.50.20", 3), binding, telemetry)  # must not raise
        finally:
            left.close()
            right.close()
