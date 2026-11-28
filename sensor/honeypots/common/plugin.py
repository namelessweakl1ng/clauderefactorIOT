"""Protocol-plugin contract for persona services.

A plugin implements one protocol. The shared runtime (``common/runtime.py``)
owns sockets, connection limits, time/message bounds, telemetry envelopes and
the UDP reflection guard; plugins only *frame*, *parse* and *reply*, so every
plugin is unit-testable without sockets.

TCP plugins return a :class:`Conversation` per connection. Each received message
yields a :class:`Reply` with bytes to send, zero or more telemetry *details*
dicts, and whether to close. UDP plugins implement :meth:`ProtocolPlugin.datagram`.

Design references: RIoTPot's service interface (name/network/port/interaction)
and per-connection middleware chain; OpenCanary's config-driven modules.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any, ClassVar

REGISTRY: dict[str, type["ProtocolPlugin"]] = {}


class PluginConfigError(ValueError):
    """A persona supplied invalid options for a plugin."""


class FrameError(Exception):
    """The peer sent a message that cannot be framed within the bounds."""


@dataclass
class Reply:
    data: bytes = b""
    events: list[dict[str, Any]] = field(default_factory=list)
    close: bool = False


@dataclass(frozen=True)
class PersonaContext:
    """What a plugin may know about the device it is impersonating."""

    persona_id: str
    name: str
    device_type: str
    vendor: str
    model: str
    firmware: str
    hostname: str
    credentials: tuple[tuple[str, str], ...]

    def accepts(self, username: str | None, password: str | None) -> bool:
        return (username or "", password or "") in self.credentials


def register(cls: type["ProtocolPlugin"]) -> type["ProtocolPlugin"]:
    if cls.name in REGISTRY:
        raise ValueError(f"duplicate plugin {cls.name!r}")
    REGISTRY[cls.name] = cls
    return cls


class Conversation:
    """Per-connection protocol state. Subclasses override :meth:`handle`."""

    def __init__(self, plugin: "ProtocolPlugin", client: tuple[str, int]) -> None:
        self.plugin = plugin
        self.client = client
        self.state: dict[str, Any] = {}

    @property
    def hardening(self) -> frozenset[str]:
        return self.state.get("hardening") or frozenset()

    def accepts(self, username: str | None, password: str | None) -> bool:
        """Honey-credential check honouring the RL ``deny_auth`` hardening effect."""
        return "deny_auth" not in self.hardening and self.plugin.persona.accepts(username, password)

    def greeting(self) -> Reply | None:
        """Bytes sent on connect before the client speaks (banners)."""
        return None

    def read(self, connection: socket.socket) -> bytes | None:
        """Read one framed message; ``None`` on orderly close."""
        return self.plugin.read_message(connection, self)

    def handle(self, message: bytes) -> Reply:
        raise NotImplementedError


class ProtocolPlugin:
    """Base class. Subclasses set the ClassVars and implement framing/handling."""

    name: ClassVar[str]
    protocol: ClassVar[str]  # normalized network.protocol value
    transport: ClassVar[str] = "tcp"
    interaction: ClassVar[str] = "low"  # low | medium (never "high": nothing executes)
    default_port: ClassVar[int]
    #: Upper bounds the persona may lower but never raise.
    max_messages_limit: ClassVar[int] = 256
    max_seconds_limit: ClassVar[float] = 300.0
    read_timeout: ClassVar[float] = 5.0
    #: True when the plugin applies posture deception itself (legacy personas).
    handles_posture: ClassVar[bool] = False
    #: UDP plugins whose ``datagram`` accepts the per-source hardening effects.
    hardening_aware: ClassVar[bool] = False

    def __init__(self, persona: PersonaContext, options: dict[str, Any] | None = None) -> None:
        self.persona = persona
        self.options = self.validate_options(dict(options or {}))

    # -- configuration ----------------------------------------------------- #
    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        """Return normalized options or raise :class:`PluginConfigError`."""
        if options:
            raise PluginConfigError(f"{cls.name}: plugin takes no options (got {sorted(options)})")
        return options

    # -- TCP --------------------------------------------------------------- #
    def conversation(self, client: tuple[str, int]) -> Conversation:
        raise NotImplementedError(f"{self.name} is not a TCP plugin")

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        """Default framing: one bounded CRLF/LF-terminated line (pipelining-safe)."""
        return read_line(connection, 1024, self.read_timeout, conversation.state.setdefault("_buffer", bytearray()))

    # -- UDP --------------------------------------------------------------- #
    def datagram(self, data: bytes, client: tuple[str, int]) -> Reply:
        raise NotImplementedError(f"{self.name} is not a UDP plugin")


def read_line(connection: socket.socket, limit: int, timeout: float, buffer: bytearray) -> bytes | None:
    """Read one newline-terminated line of at most ``limit`` bytes.

    ``buffer`` is owned by the conversation: bytes after the newline in the same
    segment stay in it for the next call, so pipelined commands (``USER``+``PASS``
    in one packet, as scanners send them) are not dropped.
    """
    connection.settimeout(timeout)
    try:
        while b"\n" not in buffer:
            if len(buffer) >= limit:
                raise FrameError("line too long")
            chunk = connection.recv(min(512, limit - len(buffer)))
            if not chunk:
                if not buffer:
                    return None
                line = bytes(buffer)
                buffer.clear()
                return line
            buffer.extend(chunk)
    except socket.timeout as exc:
        raise FrameError("read timeout") from exc
    index = buffer.index(b"\n") + 1
    line = bytes(buffer[:index])
    del buffer[:index]
    return line


def recv_exact(connection: socket.socket, length: int, timeout: float) -> bytes:
    connection.settimeout(timeout)
    data = bytearray()
    try:
        while len(data) < length:
            chunk = connection.recv(length - len(data))
            if not chunk:
                raise FrameError("incomplete frame")
            data.extend(chunk)
    except socket.timeout as exc:
        raise FrameError("read timeout") from exc
    return bytes(data)


def option(options: dict[str, Any], key: str, kind: type | tuple[type, ...], default: Any, plugin: str) -> Any:
    value = options.get(key, default)
    kinds = kind if isinstance(kind, tuple) else (kind,)
    # bool is a subclass of int; never accept it where a number is expected.
    if (isinstance(value, bool) and bool not in kinds) or not isinstance(value, kinds):
        names = "/".join(k.__name__ for k in kinds)
        raise PluginConfigError(f"{plugin}: option {key!r} must be {names}")
    return value
