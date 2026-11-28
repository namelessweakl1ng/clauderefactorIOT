"""Multi-service runtime: hosts every service of one persona in one process.

Bounds enforced here, never by plugins:

* per-source concurrent TCP connections (shared with the legacy server);
* per-connection message count and wall-clock lifetime
  (``min(persona interaction limit, plugin hard limit)``);
* UDP reflection guard: per-source and global token buckets, plus a reply-size
  cap of ``AMPLIFICATION_FACTOR × request`` -- larger replies are suppressed and
  logged, so a spoofed source cannot turn the sensor into an amplifier;
* posture-driven bounded delay before a suspicious source is served.

Every message produces a schema-v2 JSONL envelope (``docs/adr/0003``).
"""

from __future__ import annotations

import os
import socket
import socketserver
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from common.community_id import community_id
from common.hardening import ELEVATED, connection_delay, hardening_for
from common.plugin import FrameError, ProtocolPlugin, Reply
from common.server import _acquire_slot, _release_slot
from common.telemetry import write_jsonl

SCHEMA_VERSION = 2
AMPLIFICATION_FACTOR = 10
UDP_PER_SOURCE_RATE = float(os.getenv("SENSOR_UDP_PER_SOURCE_RATE", "5"))
UDP_PER_SOURCE_BURST = float(os.getenv("SENSOR_UDP_PER_SOURCE_BURST", "10"))
UDP_GLOBAL_RATE = float(os.getenv("SENSOR_UDP_GLOBAL_RATE", "200"))
_ALLOWED_CATEGORIES = {"authentication", "network", "web", "process", "session"}
_ALLOWED_OUTCOMES = {"success", "failure", "unknown"}


class TokenBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate, self.burst = rate, burst
        self.tokens, self.updated = burst, 0.0

    def take(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        self.tokens = min(self.burst, self.tokens + max(0.0, now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class ReflectionGuard:
    """Rate and size limits for UDP replies (thread-safe)."""

    def __init__(
        self, per_source_rate: float = UDP_PER_SOURCE_RATE, per_source_burst: float = UDP_PER_SOURCE_BURST, global_rate: float = UDP_GLOBAL_RATE
    ) -> None:
        self._lock = threading.Lock()
        self._sources: dict[str, TokenBucket] = {}
        self._global = TokenBucket(global_rate, global_rate)
        self.per_source_rate, self.per_source_burst = per_source_rate, per_source_burst

    def admit(self, source_ip: str, now: float | None = None) -> bool:
        with self._lock:
            if len(self._sources) > 10_000:  # bound memory under spoofed floods
                self._sources.clear()
            bucket = self._sources.setdefault(source_ip, TokenBucket(self.per_source_rate, self.per_source_burst))
            return bucket.take(now) and self._global.take(now)

    @staticmethod
    def size_ok(request: bytes, reply: bytes) -> bool:
        return len(reply) <= AMPLIFICATION_FACTOR * max(1, len(request))


@dataclass
class ServiceBinding:
    plugin: ProtocolPlugin
    service_name: str
    port: int
    public_port: int
    max_messages: int
    max_seconds: float
    honeypot_id: str | None = None


class Telemetry:
    """Builds schema-v2 envelopes and writes them as JSONL."""

    def __init__(self, persona: Any, log_path: str, sensor_ip: str | None) -> None:
        self.persona = persona
        self.log_path = log_path
        self.sensor_ip = sensor_ip or None
        self.redact_credentials = persona.logging.get("credentials", "full") == "redact"
        self.payload_bytes = int(persona.logging.get("payload_bytes", 256))
        self._stats: dict[str, dict[str, Any]] = {}
        self._stats_lock = threading.Lock()

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._stats_lock:
            return {name: dict(values) for name, values in self._stats.items()}

    def envelope(
        self,
        binding: ServiceBinding,
        client: tuple[str, int],
        details: dict[str, Any],
        *,
        connection_id: str,
        sequence: int,
        payload: bytes | None = None,
        hardening: tuple[frozenset[str], str | None] | None = None,
    ) -> dict[str, Any]:
        plugin = binding.plugin
        category = (
            details.get("category") if details.get("category") in _ALLOWED_CATEGORIES else ("authentication" if details.get("authentication") else "network")
        )
        outcome = details.get("outcome") if details.get("outcome") in _ALLOWED_OUTCOMES else "unknown"
        event: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "category": category,
            "type": details.get("type", "info"),
            "action": str(details.get("action") or "request")[:64],
            "outcome": outcome,
            "source_ip": client[0],
            "source_port": client[1],
            "destination_port": binding.public_port,
            "protocol": plugin.protocol,
            "transport": plugin.transport,
            "service": binding.service_name,
            "honeypot_id": binding.honeypot_id or f"{self.persona.id}-{binding.service_name}",
            "honeypot_type": plugin.name.replace("-", "_"),
            "summary": str(details.get("summary") or f"{plugin.protocol} {details.get('action') or 'request'}")[:200],
            "plugin": plugin.name,
            "interaction": plugin.interaction,
            "connection_id": connection_id,
            "sequence": sequence,
            "persona": {
                "id": self.persona.id,
                "name": self.persona.name,
                "device_type": self.persona.device_type,
                "vendor": self.persona.vendor,
                "model": self.persona.model,
                "firmware": self.persona.firmware,
            },
        }
        if self.sensor_ip:
            flow = community_id(client[0], client[1], self.sensor_ip, binding.public_port, plugin.transport)
            if flow:
                event["community_id"] = flow
        for key in ("authentication", "url", "http", "process", plugin.protocol, "iot", "mqtt"):
            if isinstance(details.get(key), dict) and details[key]:
                event[key] = dict(details[key])
        if self.redact_credentials and "authentication" in event and "password" in event["authentication"]:
            event["authentication"]["password"] = "<redacted>"
        if hardening and hardening[0]:
            # Which RL hardening action shaped this interaction (dashboard + reward audit).
            event["hardening"] = {"actions": sorted(hardening[0]), "decision_id": hardening[1]}
        if payload is not None and self.payload_bytes > 0:
            event["payload_excerpt"] = payload[: self.payload_bytes].decode("latin-1")
        return event

    def write(self, event: dict[str, Any]) -> None:
        with self._stats_lock:
            stats = self._stats.setdefault(event["service"], {"events": 0, "errors": 0, "last_event_at": None})
            stats["events"] += 1
            stats["last_event_at"] = event["timestamp"]
            if event.get("action") in {"malformed", "parser_error"}:
                stats["errors"] += 1
        write_jsonl(self.log_path, event)


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def tcp_handler(binding: ServiceBinding, telemetry: Telemetry):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            source = self.client_address[0]
            if not _acquire_slot(source):
                return
            try:
                serve_connection(self.request, self.client_address, binding, telemetry)
            finally:
                _release_slot(source)

    return Handler


def serve_connection(connection: socket.socket, client: tuple[str, int], binding: ServiceBinding, telemetry: Telemetry) -> int:
    """Run one bounded conversation; returns the number of messages handled."""
    connection_id = uuid.uuid4().hex
    effects, decision_id = hardening_for(client[0])
    if "tarpit" in effects and not binding.plugin.handles_posture:
        connection_delay(ELEVATED)  # bounded 150-500 ms
    conversation = binding.plugin.conversation(client)
    conversation.state["hardening"] = effects
    sequence = 0
    deadline = time.monotonic() + binding.max_seconds

    def emit(reply: Reply, payload: bytes | None) -> bool:
        nonlocal sequence
        for details in reply.events:
            sequence += 1
            envelope = telemetry.envelope(
                binding, client, details, connection_id=connection_id, sequence=sequence, payload=payload, hardening=(effects, decision_id)
            )
            telemetry.write(envelope)
        if reply.data:
            try:
                connection.sendall(reply.data)
            except OSError:
                return False
        return not reply.close

    greeting = conversation.greeting()
    if greeting is not None and not emit(greeting, None):
        return 0
    handled = 0
    while handled < binding.max_messages and time.monotonic() < deadline:
        try:
            message = conversation.read(connection)
        except FrameError as exc:
            emit(
                Reply(
                    events=[{"category": "network", "action": "malformed", "outcome": "failure", "summary": f"{binding.plugin.protocol} framing error: {exc}"}],
                    close=True,
                ),
                None,
            )
            break
        except OSError:
            break
        if message is None:
            break
        handled += 1
        try:
            reply = conversation.handle(message)
        except Exception as exc:  # a parser bug must never crash the service
            reply = Reply(
                events=[{"category": "network", "action": "parser_error", "outcome": "failure", "summary": f"unhandled input ({type(exc).__name__})"}],
                close=True,
            )
        if not emit(reply, message):
            break
    else:
        if handled >= binding.max_messages:
            emit(Reply(events=[{"category": "session", "action": "message_limit", "type": "end", "summary": "interaction bound reached"}], close=True), None)
    return handled


def udp_handler(binding: ServiceBinding, telemetry: Telemetry, guard: ReflectionGuard):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data, sock = self.request
            handle_datagram(data, sock, self.client_address, binding, telemetry, guard)

    return Handler


def handle_datagram(data: bytes, sock: Any, client: tuple[str, int], binding: ServiceBinding, telemetry: Telemetry, guard: ReflectionGuard) -> bool:
    """Process one datagram; returns True if a reply was sent."""
    connection_id = uuid.uuid4().hex
    admitted = guard.admit(client[0])
    effects, decision_id = hardening_for(client[0])
    try:
        if binding.plugin.hardening_aware:
            reply = binding.plugin.datagram(data[:2048], client, effects)
        else:
            reply = binding.plugin.datagram(data[:2048], client)
    except Exception as exc:
        reply = Reply(events=[{"category": "network", "action": "parser_error", "outcome": "failure", "summary": f"unhandled datagram ({type(exc).__name__})"}])
    suppressed = None
    if reply.data and not admitted:
        suppressed = "rate_limited"
    elif reply.data and not guard.size_ok(data, reply.data):
        suppressed = "amplification_cap"
    elif reply.data and "drop_udp" in effects:
        suppressed = "hardening_drop_udp"
    for sequence, details in enumerate(reply.events, start=1):
        envelope = telemetry.envelope(binding, client, details, connection_id=connection_id, sequence=sequence, payload=data, hardening=(effects, decision_id))
        if suppressed:
            envelope["reply_suppressed"] = suppressed
        telemetry.write(envelope)
    if reply.data and suppressed is None:
        sock.sendto(reply.data, client)
        return True
    return False


def serve_persona(persona: Any, *, log_path: str, sensor_ip: str | None, host: str = "0.0.0.0") -> tuple[list[threading.Thread], Telemetry]:
    """Start every enabled service of ``persona`` on daemon threads; return (threads, telemetry)."""
    telemetry = Telemetry(persona, log_path, sensor_ip)
    guard = ReflectionGuard()
    threads = []
    for binding in persona.bindings():
        if binding.plugin.transport == "udp":
            server: socketserver.BaseServer = _UDPServer((host, binding.port), udp_handler(binding, telemetry, guard))
        else:
            server = _TCPServer((host, binding.port), tcp_handler(binding, telemetry))
        thread = threading.Thread(target=server.serve_forever, name=f"{persona.id}:{binding.service_name}", daemon=True)
        thread.server = server  # type: ignore[attr-defined]  # lets stop_servers() shut it down
        thread.start()
        threads.append(thread)
    return threads, telemetry


def stop_servers(threads: list[threading.Thread]) -> None:
    """Shut down servers started by :func:`serve_persona` (used for hot reloads)."""
    for thread in threads:
        server = getattr(thread, "server", None)
        if server is not None:
            server.shutdown()
            server.server_close()


def serve_persona_native(
    persona: Any, *, log_path: str, sensor_ip: str | None, host: str = "0.0.0.0"
) -> tuple[list[threading.Thread], Telemetry, dict[str, str]]:
    """Run a persona directly on a host (no container port mapping).

    Each service binds its *public* port on ``host``; a port that cannot be bound
    (in use, reserved, missing privileges) is reported in the returned failures
    and the other services still start, so one blocked port never takes a whole
    device persona down. Returns (threads, telemetry, {service: error}).
    """
    telemetry = Telemetry(persona, log_path, sensor_ip)
    guard = ReflectionGuard()
    threads: list[threading.Thread] = []
    failures: dict[str, str] = {}
    for binding in persona.bindings():
        binding.port = binding.public_port
        try:
            if binding.plugin.transport == "udp":
                server: socketserver.BaseServer = _UDPServer((host, binding.port), udp_handler(binding, telemetry, guard))
            else:
                server = _TCPServer((host, binding.port), tcp_handler(binding, telemetry))
        except OSError as exc:
            failures[binding.service_name] = f"{binding.plugin.transport}/{binding.port}: {exc.strerror or exc}"
            continue
        thread = threading.Thread(target=server.serve_forever, name=f"{persona.id}:{binding.service_name}", daemon=True)
        thread.server = server  # type: ignore[attr-defined]
        thread.start()
        threads.append(thread)
    return threads, telemetry, failures
