"""IT/IoT service emulators: Telnet shell, SNMP, Redis, SIP, TFTP, VNC, RDP.

Service selection follows the reference projects (RIoTPot, OpenCanary,
EventHorizon): the protocols IoT botnets and opportunistic scanners hit most.
All are bounded: nothing is executed, transferred, stored, or proxied; replies
are canned and small (UDP replies also pass the runtime's reflection guard).
"""

from __future__ import annotations

import re
import socket
import struct
from typing import Any

from common.plugin import Conversation, FrameError, PluginConfigError, ProtocolPlugin, Reply, option, read_line, recv_exact, register

# --------------------------------------------------------------------------- #
# Telnet with a BusyBox-style emulated shell
# --------------------------------------------------------------------------- #

IAC = 255
_IAC_SEQUENCE = re.compile(rb"\xff[\xfb-\xfe].|\xff\xfa.*?\xff\xf0|\xff.", re.S)
_SHELL_OUTPUTS = {
    "uname": "Linux",
    "uname -a": "Linux {hostname} 3.10.14 #1 SMP PREEMPT Tue Mar 3 11:02:51 CST 2020 armv7l GNU/Linux",
    "id": "uid=0(root) gid=0(root)",
    "whoami": "root",
    "hostname": "{hostname}",
    "pwd": "/",
    "ls": "bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var",
    "cat /proc/cpuinfo": "processor\t: 0\nmodel name\t: ARMv7 Processor rev 5 (v7l)\nBogoMIPS\t: 38.40\nHardware\t: {model}",
    "cat /proc/version": "Linux version 3.10.14 (build@builder) (gcc version 4.9.4) #1 SMP PREEMPT",
    "ps": (
        "  PID USER       VSZ STAT COMMAND\n    1 root      1484 S    init\n"
        "  412 root      2240 S    /usr/sbin/telnetd\n  431 root      9812 S    /app/{daemon}"
    ),
    "free": "             total       used       free\nMem:        124632      81204      43428",
    "busybox": "BusyBox v1.24.1 (2020-03-03 11:02:51 CST) multi-call binary.",
}
_SILENT = ("enable", "system", "shell", "sh", "linuxshell", "cd ", "echo", "export ", "rm ", "chmod ", "cp ", ">")


def strip_telnet(data: bytes) -> bytes:
    return _IAC_SEQUENCE.sub(b"", data)


def shell_reply(command: str, persona: Any) -> str:
    cmd = command.strip()
    names = {"hostname": persona.hostname, "model": persona.model or "IoT", "daemon": (persona.model or "dvr").lower()}
    if cmd in _SHELL_OUTPUTS:
        return _SHELL_OUTPUTS[cmd].format(**names)
    match = re.match(r"^(?:/bin/)?busybox\s+([A-Za-z0-9]+)", cmd)
    if match:
        return f"{match.group(1)}: applet not found"
    if re.match(r"^(wget|curl|tftp|ftpget)\b", cmd):
        return f"{cmd.split()[0]}: bad address"  # never fetched: no network access from the decoy
    if cmd.startswith(_SILENT) or not cmd:
        return ""
    return f"-sh: {cmd.split()[0]}: not found"


@register
class TelnetPlugin(ProtocolPlugin):
    name = "telnet"
    protocol = "telnet"
    default_port = 2323
    interaction = "medium"
    max_messages_limit = 64

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"banner", "max_failures"}:
            raise PluginConfigError("telnet: options are banner, max_failures")
        failures = option(options, "max_failures", int, 3, "telnet")
        if not 1 <= failures <= 10:
            raise PluginConfigError("telnet: max_failures must be 1..10")
        return {"banner": str(options.get("banner", ""))[:120], "max_failures": failures}

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        line = read_line(connection, 512, self.read_timeout, conversation.state.setdefault("_buffer", bytearray()))
        return None if line is None else strip_telnet(line)

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return TelnetConversation(self, client)


class TelnetConversation(Conversation):
    def greeting(self) -> Reply:
        negotiation = bytes([IAC, 251, 1, IAC, 251, 3])  # WILL ECHO, WILL SUPPRESS-GO-AHEAD
        banner = self.plugin.options["banner"] or f"{self.plugin.persona.hostname} login"
        return Reply(
            negotiation + f"\r\n{banner}: ".encode(), [{"category": "session", "type": "start", "action": "telnet_connect", "summary": "telnet connection"}]
        )

    def handle(self, message: bytes) -> Reply:
        text = message.decode("latin-1").strip()[:200]
        stage = self.state.get("stage", "login")
        if stage == "login":
            self.state.update(stage="password", username=text)
            return Reply(b"Password: ")
        if stage == "password":
            username = self.state.get("username", "")
            ok = self.accepts(username, text)
            event = {
                "category": "authentication",
                "action": "login_attempt",
                "outcome": "success" if ok else "failure",
                "authentication": {"username": username, "password": text},
                "summary": f"telnet login {username}",
            }
            if ok:
                self.state["stage"] = "shell"
                return Reply(b"\r\n\r\nBusyBox v1.24.1 built-in shell (ash)\r\n\r\n# ", [event])
            failures = self.state.get("failures", 0) + 1
            self.state.update(failures=failures, stage="login")
            close = failures >= self.plugin.options["max_failures"]
            return Reply(b"\r\nLogin incorrect\r\n" + (b"" if close else f"{self.plugin.persona.hostname} login: ".encode()), [event], close=close)
        if text in {"exit", "logout", "quit"}:
            return Reply(b"\r\n", [{"category": "session", "type": "end", "action": "telnet_logout"}], close=True)
        output = shell_reply(text, self.plugin.persona)
        event = {"category": "process", "action": "command", "outcome": "unknown", "process": {"command_line": text}, "summary": f"telnet command {text[:40]}"}
        return Reply(((output + "\r\n") if output else "").encode() + b"# ", [event])


# --------------------------------------------------------------------------- #
# SNMP v1/v2c (UDP)
# --------------------------------------------------------------------------- #

PDU_TYPES = {0xA0: "get", 0xA1: "get-next", 0xA3: "set", 0xA5: "get-bulk"}
SYSTEM_OIDS = ("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0")


class BERError(ValueError):
    pass


def _ber_read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise BERError("truncated")
    tag, length = data[offset], data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 2 or offset + count > len(data):
            raise BERError("bad length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise BERError("overrun")
    return tag, data[offset : offset + length], offset + length


def _ber(tag: int, value: bytes) -> bytes:
    if len(value) < 128:
        return bytes([tag, len(value)]) + value
    return bytes([tag, 0x82]) + struct.pack("!H", len(value)) + value


def _oid_decode(raw: bytes) -> str:
    if not raw:
        return ""
    parts, value = [str(raw[0] // 40), str(raw[0] % 40)], 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _oid_encode(oid: str) -> bytes:
    numbers = [int(x) for x in oid.split(".")]
    out = bytearray([numbers[0] * 40 + numbers[1]])
    for number in numbers[2:]:
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.insert(0, 0x80 | (number & 0x7F))
            number >>= 7
        out.extend(chunk)
    return bytes(out)


def _int(value: int) -> bytes:
    return _ber(0x02, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


@register
class SNMPPlugin(ProtocolPlugin):
    name = "snmp"
    protocol = "snmp"
    transport = "udp"
    default_port = 1161
    hardening_aware = True

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"read_communities", "write_communities", "contact", "location"}:
            raise PluginConfigError("snmp: options are read_communities, write_communities, contact, location")
        read = options.get("read_communities", ["public"])
        write = options.get("write_communities", ["private"])
        if not all(isinstance(x, list) and all(isinstance(c, str) for c in x) for x in (read, write)):
            raise PluginConfigError("snmp: communities must be lists of strings")
        return {
            "read": [c[:32] for c in read],
            "write": [c[:32] for c in write],
            "contact": str(options.get("contact", "admin@example.invalid"))[:60],
            "location": str(options.get("location", "Rack 2"))[:60],
        }

    def _mib(self) -> dict[str, tuple[int, bytes]]:
        persona = self.persona
        values = [f"{persona.vendor} {persona.model} firmware {persona.firmware}", None, self.options["contact"], persona.hostname, self.options["location"]]
        mib: dict[str, tuple[int, bytes]] = {}
        for oid, value in zip(SYSTEM_OIDS, values, strict=True):
            mib[oid] = (0x43, (8_640_000).to_bytes(4, "big")) if value is None else (0x04, value.encode()[:120])
        return mib

    def datagram(self, data: bytes, client: tuple[str, int], hardening: frozenset[str] = frozenset()) -> Reply:
        try:
            tag, message, _ = _ber_read(data, 0)
            if tag != 0x30:
                raise BERError("not a sequence")
            _, version_raw, offset = _ber_read(message, 0)
            _, community_raw, offset = _ber_read(message, offset)
            pdu_tag, pdu, _ = _ber_read(message, offset)
            _, request_id, poffset = _ber_read(pdu, 0)
            _, _, poffset = _ber_read(pdu, poffset)
            _, max_rep_or_err, poffset = _ber_read(pdu, poffset)
            _, varbinds, _ = _ber_read(pdu, poffset)
            oids, voffset = [], 0
            while voffset < len(varbinds) and len(oids) < 10:
                _, varbind, voffset = _ber_read(varbinds, voffset)
                _, oid_raw, _ = _ber_read(varbind, 0)
                oids.append(_oid_decode(oid_raw))
        except BERError as exc:
            return Reply(
                events=[{"category": "network", "action": "malformed", "outcome": "failure", "summary": "snmp malformed", "snmp": {"error": str(exc)}}]
            )
        community = community_raw.decode("latin-1")[:32]
        pdu_name = PDU_TYPES.get(pdu_tag, f"pdu_{pdu_tag:#04x}")
        version = {0: "v1", 1: "v2c"}.get(int.from_bytes(version_raw or b"\x00", "big"), "other")
        allowed = (community in self.options["read"] or community in self.options["write"]) and "deny_auth" not in hardening
        details = {"version": version, "community": community, "pdu": pdu_name, "oids": oids[:10], "write": pdu_tag == 0xA3}
        if pdu_tag == 0xA3 and allowed and (community not in self.options["write"] or "read_only" in hardening):
            details["hardening_blocked"] = "read_only" in hardening
            allowed_set = False
        else:
            allowed_set = pdu_tag == 0xA3 and allowed
        event = {
            "category": "authentication",
            "action": "snmp_" + pdu_name.replace("-", "_"),
            "outcome": "success" if allowed and (pdu_tag != 0xA3 or allowed_set) else "failure",
            "summary": f"snmp {pdu_name} community={community}",
            "snmp": details,
            "authentication": {"username": "snmp", "password": community},
        }
        if not allowed:
            return Reply(events=[event])  # real agents stay silent on a wrong community
        mib = self._mib()
        ordered = sorted(mib, key=lambda o: [int(x) for x in o.split(".")])
        results = []
        for oid in oids:
            if pdu_tag in (0xA1, 0xA5):
                following = [o for o in ordered if [int(x) for x in o.split(".")] > [int(x) for x in oid.split(".") if x.isdigit()]]
                oid = following[0] if following else oid
            value = mib.get(oid)
            results.append((oid, value or (0x80, b"")))  # noSuchObject
        error = 0
        if pdu_tag == 0xA3 and not allowed_set:
            error = 17 if community in self.options["write"] else 16  # notWritable (read-only) / authorizationError
        encoded = b"".join(_ber(0x30, _ber(0x06, _oid_encode(oid)) + _ber(tag, value)) for oid, (tag, value) in results)
        response = _ber(0xA2, _ber(0x02, request_id) + _int(error) + _int(0) + _ber(0x30, encoded))
        return Reply(_ber(0x30, _ber(0x02, version_raw) + _ber(0x04, community_raw) + response), [event])


# --------------------------------------------------------------------------- #
# Redis (RESP)
# --------------------------------------------------------------------------- #

REDIS_EXPLOIT = {"SLAVEOF", "REPLICAOF", "MODULE", "EVAL", "EVALSHA", "SCRIPT", "DEBUG", "MIGRATE"}
REDIS_WRITE = {"SET", "DEL", "FLUSHALL", "FLUSHDB", "HSET", "LPUSH", "SAVE", "BGSAVE", "CONFIG"}


@register
class RedisPlugin(ProtocolPlugin):
    name = "redis"
    protocol = "redis"
    default_port = 6379
    interaction = "low"
    max_messages_limit = 128

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"requirepass", "version"}:
            raise PluginConfigError("redis: options are requirepass, version")
        return {"requirepass": str(options.get("requirepass", "")), "version": str(options.get("version", "6.0.16"))[:16]}

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        buffer = conversation.state.setdefault("_buffer", bytearray())
        first = read_line(connection, 1024, self.read_timeout, buffer)
        if first is None or not first.startswith(b"*"):
            return first
        count = int(first[1:].strip() or 0)
        if not 0 <= count <= 16:
            raise FrameError("too many arguments")
        parts = [first]
        for _ in range(count * 2):
            line = read_line(connection, 4096, self.read_timeout, buffer)
            if line is None:
                break
            parts.append(line)
        return b"".join(parts)

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return RedisConversation(self, client)


def parse_resp(message: bytes) -> list[str]:
    text = message.decode("latin-1")
    if not text.startswith("*"):
        return text.strip().split()
    lines = text.split("\r\n")
    return [lines[i] for i in range(2, len(lines), 2)][: int(lines[0][1:] or 0)]


class RedisConversation(Conversation):
    def handle(self, message: bytes) -> Reply:
        args = parse_resp(message)
        command = (args[0].upper() if args else "")[:16]
        options = self.plugin.options
        details: dict[str, Any] = {
            "command": command,
            "args": [a[:80] for a in args[1:6]],
            "write": command in REDIS_WRITE,
            "exploit": command in REDIS_EXPLOIT,
        }
        if command == "CONFIG" and len(args) > 2 and args[1].upper() == "SET" and args[2].lower() in {"dir", "dbfilename"}:
            details["exploit"] = True  # classic cron/ssh-key write primitive
        event = {"category": "network", "action": f"redis_{command.lower() or 'empty'}", "outcome": "success", "summary": f"redis {command}", "redis": details}
        if command == "AUTH":
            password = args[-1] if len(args) > 1 else ""
            ok = bool(options["requirepass"]) and password == options["requirepass"] and "deny_auth" not in self.hardening
            self.state["authed"] = ok
            event.update(
                category="authentication",
                action="login_attempt",
                outcome="success" if ok else "failure",
                authentication={"username": args[1] if len(args) > 2 else "default", "password": password},
            )
            return Reply(b"+OK\r\n" if ok else b"-WRONGPASS invalid username-password pair\r\n", [event])
        if options["requirepass"] and not self.state.get("authed") and command not in {"PING", "QUIT"}:
            event["outcome"] = "failure"
            return Reply(b"-NOAUTH Authentication required.\r\n", [event])
        if command == "PING":
            reply = b"+PONG\r\n"
        elif command == "INFO":
            body = (
                f"# Server\r\nredis_version:{options['version']}\r\nos:Linux 5.4.0 x86_64\r\narch_bits:64\r\n"
                "tcp_port:6379\r\n# Keyspace\r\ndb0:keys=12,expires=0\r\n"
            )
            reply = f"${len(body)}\r\n{body}\r\n".encode()
        elif command == "QUIT":
            return Reply(b"+OK\r\n", [event], close=True)
        elif command in {"KEYS", "SCAN"}:
            reply = b"*2\r\n$12\r\nsession:4f2a\r\n$9\r\nqueue:jobs\r\n"
        elif command == "GET":
            reply = b"$-1\r\n"
        elif details["exploit"] or command in REDIS_WRITE:
            if "read_only" in self.hardening:
                event["outcome"] = "failure"
                reply = b"-READONLY You can't write against a read only replica.\r\n"
            else:
                reply = b"+OK\r\n"  # acknowledged, never applied
        else:
            reply = f"-ERR unknown command '{command.lower()}'\r\n".encode()
        return Reply(reply, [event])


# --------------------------------------------------------------------------- #
# SIP (UDP)
# --------------------------------------------------------------------------- #


@register
class SIPPlugin(ProtocolPlugin):
    name = "sip"
    protocol = "sip"
    transport = "udp"
    default_port = 5060

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"user_agent", "extensions"}:
            raise PluginConfigError("sip: options are user_agent, extensions")
        extensions = options.get("extensions", ["100", "101"])
        if not isinstance(extensions, list):
            raise PluginConfigError("sip: extensions must be a list")
        return {"user_agent": str(options.get("user_agent", "VoIP Phone 2.1"))[:60], "extensions": [str(e)[:16] for e in extensions]}

    def datagram(self, data: bytes, client: tuple[str, int]) -> Reply:
        text = data[:2048].decode("latin-1", "replace")
        lines = text.split("\r\n")
        parts = lines[0].split()
        if len(parts) < 3 or not parts[2].startswith("SIP/"):
            return Reply(
                events=[{"category": "network", "action": "malformed", "outcome": "failure", "summary": "sip malformed", "sip": {"error": "request line"}}]
            )
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        method = parts[0].upper()[:12]
        to_user = (re.search(r"sip:([^@;>]+)", headers.get("to", "")) or re.search(r"sip:([^@;>]+)", parts[1]) or [None, ""])[1]
        auth_user = (re.search(r'username="([^"]+)"', headers.get("authorization", "")) or [None, None])[1]
        details = {
            "method": method,
            "to_user": str(to_user)[:32],
            "from_user": (re.search(r"sip:([^@;>]+)", headers.get("from", "")) or [None, ""])[1][:32],
            "user_agent": headers.get("user-agent", "")[:80],
            "auth_user": auth_user,
        }
        known = str(to_user) in self.options["extensions"]
        if method == "OPTIONS":
            status = "200 OK"
        elif method in {"REGISTER", "INVITE"}:
            status = ("401 Unauthorized" if not auth_user else "403 Forbidden") if known else "404 Not Found"
        else:
            status = "405 Method Not Allowed"
        event: dict[str, Any] = {
            "category": "authentication" if auth_user else "network",
            "action": f"sip_{method.lower()}",
            "outcome": "failure" if status[0] in "45" else "success",
            "summary": f"sip {method} -> {status}",
            "sip": details,
        }
        if auth_user:
            event["authentication"] = {"username": auth_user}
        keep = "".join(f"{h}: {headers[h.lower()]}\r\n" for h in ("Via", "From", "To", "Call-ID", "CSeq") if h.lower() in headers)
        extra = 'WWW-Authenticate: Digest realm="voip", nonce="5a1c0f2e"\r\n' if status.startswith("401") else ""
        reply = f"SIP/2.0 {status}\r\n{keep}{extra}Server: {self.options['user_agent']}\r\nContent-Length: 0\r\n\r\n".encode()
        return Reply(reply, [event])


# --------------------------------------------------------------------------- #
# TFTP (UDP) -- every transfer is refused
# --------------------------------------------------------------------------- #


@register
class TFTPPlugin(ProtocolPlugin):
    name = "tftp"
    protocol = "tftp"
    transport = "udp"
    default_port = 6969

    def datagram(self, data: bytes, client: tuple[str, int]) -> Reply:
        if len(data) < 4:
            return Reply(events=[{"category": "network", "action": "malformed", "outcome": "failure", "summary": "tftp malformed", "tftp": {"error": "short"}}])
        opcode = struct.unpack("!H", data[:2])[0]
        fields = data[2:516].split(b"\x00")
        filename = fields[0].decode("latin-1")[:128] if fields else ""
        mode = fields[1].decode("latin-1")[:16] if len(fields) > 1 else ""
        name = {1: "RRQ", 2: "WRQ"}.get(opcode, f"op{opcode}")
        code, text = (1, b"File not found") if opcode == 1 else (2, b"Access violation")
        event = {
            "category": "network",
            "action": f"tftp_{name.lower()}",
            "outcome": "failure",
            "summary": f"tftp {name} {filename}",
            "tftp": {"opcode": name, "filename": filename, "mode": mode},
        }
        return Reply(struct.pack("!HH", 5, code) + text + b"\x00", [event])


# --------------------------------------------------------------------------- #
# VNC (RFB 3.8, VNC authentication always fails)
# --------------------------------------------------------------------------- #


@register
class VNCPlugin(ProtocolPlugin):
    name = "vnc"
    protocol = "vnc"
    default_port = 5900
    max_messages_limit = 8

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        stage = conversation.state.get("stage", "version")
        connection.settimeout(self.read_timeout)
        try:
            if stage == "version":
                return recv_exact(connection, 12, self.read_timeout)
            if stage == "security":
                return recv_exact(connection, 1, self.read_timeout)
            if stage == "auth":
                return recv_exact(connection, 16, self.read_timeout)
        except FrameError:
            return None
        return None

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return VNCConversation(self, client)


class VNCConversation(Conversation):
    def greeting(self) -> Reply:
        return Reply(b"RFB 003.008\n")

    def handle(self, message: bytes) -> Reply:
        stage = self.state.get("stage", "version")
        if stage == "version":
            self.state.update(stage="security", client_version=message.decode("latin-1").strip())
            return Reply(b"\x01\x02")  # one security type: VNC authentication
        if stage == "security":
            self.state["stage"] = "auth"
            return Reply(b"\x00" * 4 + b"TRAPSIG-CHALLNGE"[:12])  # 16-byte challenge
        reason = b"Authentication failed"
        event = {
            "category": "authentication",
            "action": "login_attempt",
            "outcome": "failure",
            "summary": "vnc authentication",
            "authentication": {"username": "vnc"},
            "vnc": {"client_version": self.state.get("client_version"), "security_type": 2},
        }
        return Reply(struct.pack("!I", 1) + struct.pack("!I", len(reason)) + reason, [event], close=True)


# --------------------------------------------------------------------------- #
# RDP (X.224 connection request with mstshash cookie)
# --------------------------------------------------------------------------- #


@register
class RDPPlugin(ProtocolPlugin):
    name = "rdp"
    protocol = "rdp"
    default_port = 3389
    max_messages_limit = 2

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        if conversation.state.get("done"):
            return None
        connection.settimeout(self.read_timeout)
        try:
            first = connection.recv(1)
        except socket.timeout as exc:
            raise FrameError("read timeout") from exc
        if not first:
            return None
        header = first + recv_exact(connection, 3, self.read_timeout)
        length = struct.unpack("!H", header[2:4])[0]
        if not 11 <= length <= 512:
            raise FrameError("invalid TPKT length")
        return header + recv_exact(connection, length - 4, self.read_timeout)

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return RDPConversation(self, client)


class RDPConversation(Conversation):
    def handle(self, message: bytes) -> Reply:
        self.state["done"] = True
        cookie = re.search(rb"Cookie: mstshash=([^\r\n]{1,64})", message)
        user = cookie.group(1).decode("latin-1") if cookie else None
        requested = struct.unpack("<I", message[-4:])[0] if len(message) >= 19 and message[-8] == 0x01 else 0
        details = {"cookie_user": user, "requested_protocols": requested}
        event: dict[str, Any] = {
            "category": "authentication" if user else "network",
            "action": "login_attempt" if user else "rdp_connect",
            "outcome": "failure",
            "summary": f"rdp connection request {user or ''}",
            "rdp": details,
        }
        if user:
            event["authentication"] = {"username": user}
        # Connection confirm with RDP_NEG_FAILURE (SSL required by server): the
        # client learns nothing more; the decoy never speaks TLS or CredSSP.
        confirm = bytes([0x0E, 0xD0, 0, 0, 0x12, 0x34, 0x00, 0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00])
        return Reply(struct.pack("!BBH", 3, 0, len(confirm) + 4) + confirm, [event], close=True)
