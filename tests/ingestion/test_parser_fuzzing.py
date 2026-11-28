"""Property/fuzz tests for the honeypot parsers against hostile input.

The personas parse attacker-controlled bytes directly. These tests throw random
and boundary payloads at the parsers and assert they fail *safely* -- a controlled
exception or a bounded result, never an unhandled crash, and never an unbounded
allocation.
"""

import random
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

import common.server as server  # noqa: E402
from camera.persona import CameraPersona  # noqa: E402
from common.protocols import http_details  # noqa: E402
from iot_service.persona import IoTServicePersona  # noqa: E402
from mqtt.persona import MQTTPersona  # noqa: E402
from router.persona import RouterPersona  # noqa: E402

SEED = 1234
PERSONAS = (CameraPersona, RouterPersona, IoTServicePersona, MQTTPersona)


def random_bytes(rng, max_len=512):
    return bytes(rng.randint(0, 255) for _ in range(rng.randint(0, max_len)))


@pytest.mark.parametrize("persona_cls", PERSONAS)
def test_personas_never_crash_on_garbage(persona_cls):
    rng = random.Random(SEED)
    persona = persona_cls()
    for _ in range(300):
        data = random_bytes(rng)
        try:
            details = persona.parse(data)
            if isinstance(details, dict):
                details.setdefault("source_ip", "192.0.2.1")
                persona.response(details)
        except (ValueError, KeyError, IndexError, UnicodeDecodeError):
            # Controlled, expected rejections of malformed input are fine.
            pass


def test_http_details_handles_boundary_and_garbage():
    rng = random.Random(SEED)
    for payload in (b"", b"GET", b"GET /\r\n", b"\x00\x00\x00", b"GET / HTTP/1.1\r\nContent-Length: nope\r\n\r\n"):
        result = http_details(payload)
        assert isinstance(result, dict) and "path" in result and "method" in result
    for _ in range(200):
        result = http_details(random_bytes(rng))
        assert isinstance(result, dict)


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_connection_cap_sheds_excess_connections(monkeypatch):
    # Force a tiny cap and verify a slot beyond it is refused, then released.
    monkeypatch.setattr(server, "MAX_CONNECTIONS_PER_IP", 2)
    with server._active_lock:
        server._active_connections.clear()
    assert server._acquire_slot("10.0.0.1") is True
    assert server._acquire_slot("10.0.0.1") is True
    assert server._acquire_slot("10.0.0.1") is False  # over the cap
    assert server._acquire_slot("10.0.0.2") is True  # a different source is unaffected
    server._release_slot("10.0.0.1")
    assert server._acquire_slot("10.0.0.1") is True  # slot freed
    # Cleanup.
    for ip in ("10.0.0.1", "10.0.0.2"):
        while server._active_connections.get(ip):
            server._release_slot(ip)


def test_unbounded_cap_is_fail_open(monkeypatch):
    monkeypatch.setattr(server, "MAX_CONNECTIONS_PER_IP", 0)
    assert all(server._acquire_slot("10.0.0.9") for _ in range(100))


def test_mqtt_frame_reader_rejects_oversized_without_allocating(monkeypatch):
    # A declared remaining-length far beyond the cap must be rejected, not buffered.
    rng = random.Random(SEED)
    for _ in range(50):
        _ = rng.random()
    # Build a pipe of sockets to feed read_mqtt_frame controlled bytes.
    server_sock = socket.socket()
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]
    result = {}

    def accept():
        conn, _ = server_sock.accept()
        try:
            from common.server import ProtocolReadError, read_mqtt_frame

            try:
                read_mqtt_frame(conn)
                result["outcome"] = "read"
            except ProtocolReadError:
                result["outcome"] = "rejected"
        finally:
            conn.close()

    thread = threading.Thread(target=accept)
    thread.start()
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    # CONNECT-ish byte + a huge multi-byte remaining length (~268M), then nothing.
    client.sendall(b"\x10\xff\xff\xff\x7f")
    client.close()
    thread.join(timeout=3)
    server_sock.close()
    assert result.get("outcome") == "rejected"
