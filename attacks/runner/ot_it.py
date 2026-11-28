"""Bounded clients for the OT/IT service personas (S7, BACnet, EtherNet/IP, tank
gauge, SNMP, Redis, SIP, TFTP, VNC, RDP, and embedded-device telnet).

Same contract as :mod:`attacks.runner.protocols`: one validated ``target``, one
port, short timeouts, at most ``MAX_REQUESTS_PER_STEP`` requests, and no real
payload. TFTP never transfers a file, Redis "exploit" commands only reach the
decoy's emulated keyspace, and dropper URLs point at TEST-NET addresses.
"""

from __future__ import annotations

import random
import socket
import struct
from typing import Any

from .protocols import MAX_REQUESTS_PER_STEP, ExpectedRejection, _cap, _udp


def _read_until(connection: socket.socket, tokens: tuple[bytes, ...], limit: int = 8192) -> bytes:
    """Read until any token appears, the peer closes, or a short timeout."""
    data = b""
    connection.settimeout(2)
    while len(data) < limit and not any(token in data for token in tokens):
        try:
            chunk = connection.recv(1024)
        except (socket.timeout, ConnectionResetError):
            break
        if not chunk:
            break
        data += chunk
    return data


def _tcp_exchange(target: str, port: int, messages: list[bytes]) -> list[bytes]:
    replies = []
    with socket.create_connection((target, port), timeout=3) as connection:
        connection.settimeout(2)
        for message in _cap(messages):
            connection.sendall(message)
            try:
                replies.append(connection.recv(4096))
            except (socket.timeout, ConnectionResetError):
                replies.append(b"")
            if not replies[-1]:
                break
    return replies


# --------------------------------------------------------------------------- #
# Telnet on an embedded device (BusyBox shell persona, not Cowrie)
# --------------------------------------------------------------------------- #


def iot_telnet(target: str, port: int, step: dict[str, Any]) -> None:
    """Try a bounded credential list in one connection; run commands after a success."""
    credentials = _cap(list(step.get("credentials") or [[step.get("username", "admin"), step.get("password", "admin")]]))
    commands = _cap(list(step.get("commands") or []))
    with socket.create_connection((target, port), timeout=3) as connection:
        _read_until(connection, (b"login: ",))
        logged_in = False
        for username, password in credentials:
            connection.sendall(f"{username}\r\n".encode())
            _read_until(connection, (b"Password: ",))
            connection.sendall(f"{password}\r\n".encode())
            reply = _read_until(connection, (b"# ", b"login: "))
            if b"# " in reply:
                logged_in = True
                break
            if b"login: " not in reply:  # lockout closed the connection
                break
        if not logged_in:
            raise ExpectedRejection("telnet login refused")
        for command in commands:
            connection.sendall(f"{command}\r\n".encode())
            _read_until(connection, (b"# ",))
        connection.sendall(b"exit\r\n")


# --------------------------------------------------------------------------- #
# Siemens S7comm (ISO-on-TCP)
# --------------------------------------------------------------------------- #

S7_JOB_FUNCTIONS = {"read_var": 0x04, "write_var": 0x05, "request_download": 0x1A, "plc_stop": 0x29}


def _tpkt(payload: bytes) -> bytes:
    return struct.pack("!BBH", 3, 0, len(payload) + 4) + payload


def _s7(rosctr: int, params: bytes, data: bytes = b"", pdu_ref: int = 1) -> bytes:
    header = b"\x32" + bytes([rosctr]) + b"\x00\x00" + struct.pack("!HHH", pdu_ref, len(params), len(data))
    return _tpkt(b"\x02\xf0\x80" + header + params + data)


def s7_frames(step: dict[str, Any]) -> list[bytes]:
    frames = [
        _tpkt(b"\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"),  # COTP CR, rack 0 slot 2
        _s7(0x01, b"\xf0\x00\x00\x01\x00\x01\x01\xe0"),  # setup communication
    ]
    for ref, op in enumerate(_cap(list(step.get("operations") or ["identify"])), start=2):
        if op == "identify":  # SZL 0x0011 (module identification) via userdata
            frames.append(_s7(0x07, b"\x00\x01\x12\x04\x11\x44\x01\x00", b"\xff\x09\x00\x04\x00\x11\x00\x00", ref))
        else:
            frames.append(_s7(0x01, bytes([S7_JOB_FUNCTIONS[op]]) + b"\x01", pdu_ref=ref))
    return frames


def s7(target: str, port: int, step: dict[str, Any]) -> None:
    replies = _tcp_exchange(target, port, s7_frames(step))
    if not replies or len(replies[0]) < 6 or replies[0][5] != 0xD0:
        raise ExpectedRejection("S7 connection refused")
    jobs = replies[2:]
    # An ack-data header carries error class/code at bytes 17..18; non-zero means refused.
    if jobs and all(len(r) < 19 or r[17:19] != b"\x00\x00" for r in jobs):
        raise ExpectedRejection("every S7 job was refused")


# --------------------------------------------------------------------------- #
# BACnet/IP (UDP)
# --------------------------------------------------------------------------- #

BACNET_APDUS = {
    "who_is": b"\x10\x08",
    "read_object_name": b"\x00\x05\x01\x0c\x0c\x02\x00\x10\x92\x19\x4d",
    "read_model_name": b"\x00\x05\x02\x0c\x0c\x02\x00\x10\x92\x19\x46",
    "write_property": b"\x00\x05\x03\x0f\x0c\x00\x80\x00\x01\x19\x55\x3e\x44\x42\x48\x00\x00\x3f",
}


def bacnet(target: str, port: int, step: dict[str, Any]) -> None:
    services = _cap(list(step.get("services") or ["who_is"]))
    refused = 0
    for name in services:
        body = b"\x01\x04" + BACNET_APDUS[name]
        reply = _udp(target, port, b"\x81\x0a" + struct.pack("!H", len(body) + 4) + body)
        if reply is None or len(reply) < 7 or reply[6] >> 4 in (5, 6, 7):  # error / reject / abort PDU
            refused += 1
    if refused == len(services):
        raise ExpectedRejection("every BACnet request was refused or unanswered")


# --------------------------------------------------------------------------- #
# EtherNet/IP encapsulation + CIP
# --------------------------------------------------------------------------- #


def _enip(command: int, data: bytes = b"", session: int = 0) -> bytes:
    return struct.pack("<HHII8sI", command, len(data), session, 0, b"trapsig0", 0) + data


def _cip_send(session: int, service: int) -> bytes:
    cip = bytes([service, 0x02, 0x20, 0x01, 0x24, 0x01])  # service, path: class 0x01 instance 1
    items = struct.pack("<IHH", 0, 10, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
    return _enip(0x6F, items, session)


def enip(target: str, port: int, step: dict[str, Any]) -> None:
    operations = _cap(list(step.get("operations") or ["list_identity"]))
    answered = 0
    with socket.create_connection((target, port), timeout=3) as connection:
        connection.settimeout(2)
        session = 0
        for op in operations:
            if op == "list_identity":
                connection.sendall(_enip(0x63))
            elif op == "register_session":
                connection.sendall(_enip(0x65, struct.pack("<HH", 1, 0)))
            elif op in {"get_attributes", "set_attribute"}:
                connection.sendall(_cip_send(session, 0x01 if op == "get_attributes" else 0x10))
            else:
                raise ValueError(f"unsupported EtherNet/IP operation: {op}")
            try:
                reply = connection.recv(4096)
            except socket.timeout:
                continue
            if not reply:
                break
            if op == "register_session" and len(reply) >= 8:
                session = struct.unpack("<I", reply[4:8])[0]
            answered += len(reply) >= 24 and struct.unpack("<I", reply[8:12])[0] == 0
    if not answered:
        raise ExpectedRejection("EtherNet/IP requests were refused")


# --------------------------------------------------------------------------- #
# Automatic tank gauge (TLS-350 style serial-over-TCP commands)
# --------------------------------------------------------------------------- #


def atg(target: str, port: int, step: dict[str, Any]) -> None:
    commands = [b"\x01" + c.encode("ascii")[:40] + b"\n" for c in _cap(list(step.get("commands") or ["I20100"]))]
    replies = _tcp_exchange(target, port, commands)
    if not replies or all(not r or r.startswith(b"\x019999") for r in replies):
        raise ExpectedRejection("tank gauge rejected every command")


# --------------------------------------------------------------------------- #
# SNMP v1/v2c (UDP)
# --------------------------------------------------------------------------- #


def _ber(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(chunk)
    return out


SNMP_PDUS = {"get": 0xA0, "get_next": 0xA1, "set": 0xA3}


def snmp_message(community: str, pdu: str = "get", oid: str = "1.3.6.1.2.1.1.1.0", value: str | None = None) -> bytes:
    encoded = _ber(0x04, value.encode()[:64]) if value is not None else b"\x05\x00"
    varbind = _ber(0x30, _ber(0x06, _oid(oid)) + encoded)
    request_id = _ber(0x02, struct.pack("!H", random.randint(1, 0x7FFF)))
    body = request_id + _ber(0x02, b"\x00") + _ber(0x02, b"\x00") + _ber(0x30, varbind)
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, community.encode()[:32]) + _ber(SNMP_PDUS[pdu], body))


def snmp(target: str, port: int, step: dict[str, Any]) -> None:
    communities = list(step.get("communities") or [step.get("community", "public")])
    templates = step.get("requests") or [{"pdu": "get", "oid": "1.3.6.1.2.1.1.1.0"}]
    requests = _cap([(c, r) for c in communities for r in templates])
    answered = 0
    for community, request in requests:
        message = snmp_message(community, request.get("pdu", "get"), request.get("oid", "1.3.6.1.2.1.1.1.0"), request.get("value"))
        answered += _udp(target, port, message) is not None
    if not answered:
        raise ExpectedRejection("no SNMP community was answered")


# --------------------------------------------------------------------------- #
# Redis (RESP)
# --------------------------------------------------------------------------- #


def resp(*args: str) -> bytes:
    return (f"*{len(args)}\r\n" + "".join(f"${len(a.encode())}\r\n{a}\r\n" for a in args)).encode()


def redis(target: str, port: int, step: dict[str, Any]) -> None:
    commands = [resp(*[str(a) for a in command]) for command in _cap(list(step.get("commands") or [["PING"]]))]
    replies = _tcp_exchange(target, port, commands)
    if not replies or all(not r or r.startswith(b"-") for r in replies):
        raise ExpectedRejection("Redis refused every command")


# --------------------------------------------------------------------------- #
# SIP (UDP)
# --------------------------------------------------------------------------- #


def sip_message(method: str, extension: str, target: str, user_agent: str) -> bytes:
    branch, tag, call = random.randbytes(4).hex(), random.randbytes(3).hex(), random.randbytes(6).hex()
    return (
        f"{method} sip:{extension}@{target} SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5070;branch=z9hG4bK{branch}\r\n"
        f"Max-Forwards: 70\r\nFrom: <sip:{extension}@{target}>;tag={tag}\r\nTo: <sip:{extension}@{target}>\r\n"
        f"Call-ID: {call}\r\nCSeq: 1 {method}\r\nContact: <sip:{extension}@192.0.2.10:5070>\r\n"
        f"User-Agent: {user_agent}\r\nContent-Length: 0\r\n\r\n"
    ).encode()


def sip(target: str, port: int, step: dict[str, Any]) -> None:
    extensions = _cap(list(step.get("extensions") or [step.get("extension", "100")]))
    method = str(step.get("method", "OPTIONS")).upper()
    user_agent = str(step.get("user_agent", "Zoiper rv2.10.19"))
    replies = [_udp(target, port, sip_message(method, str(ext), target, user_agent)) for ext in extensions]
    if all(r is None or not r.startswith(b"SIP/2.0 2") for r in replies):
        raise ExpectedRejection("no SIP request was accepted")


# --------------------------------------------------------------------------- #
# TFTP (UDP): requests only; the decoy answers every RRQ/WRQ with an ERROR.
# --------------------------------------------------------------------------- #


def tftp(target: str, port: int, step: dict[str, Any]) -> None:
    files = _cap(list(step.get("files") or [step.get("file", "config.xml")]))
    opcode = 2 if step.get("operation", "read") == "write" else 1
    replies = [_udp(target, port, struct.pack("!H", opcode) + str(name).encode()[:100] + b"\x00octet\x00") for name in files]
    if all(r is None or r[:2] == b"\x00\x05" for r in replies):
        raise ExpectedRejection("TFTP transfer refused")


# --------------------------------------------------------------------------- #
# VNC (RFB 3.8) and RDP (X.224 connection request)
# --------------------------------------------------------------------------- #


def vnc(target: str, port: int, step: dict[str, Any]) -> None:
    attempts = int(step.get("attempts", 1))
    if not 1 <= attempts <= MAX_REQUESTS_PER_STEP:
        raise ValueError(f"a step may issue at most {MAX_REQUESTS_PER_STEP} requests")
    accepted = 0
    for _ in range(attempts):
        with socket.create_connection((target, port), timeout=3) as connection:
            connection.settimeout(2)
            _read_until(connection, (b"\n",), 12)
            connection.sendall(b"RFB 003.008\n")
            connection.recv(16)
            connection.sendall(b"\x02")  # VNC authentication
            connection.recv(16)
            connection.sendall(random.randbytes(16))  # DES response to a password guess
            accepted += connection.recv(64)[:4] == b"\x00\x00\x00\x00"
    if not accepted:
        raise ExpectedRejection("VNC authentication failed")


def rdp(target: str, port: int, step: dict[str, Any]) -> None:
    users = _cap(list(step.get("usernames") or [step.get("username", "administrator")]))
    for user in users:
        cookie = f"Cookie: mstshash={str(user)[:32]}\r\n".encode()
        x224 = bytes([6 + len(cookie) + 8, 0xE0, 0, 0, 0, 0, 0]) + cookie + b"\x01\x00\x08\x00\x03\x00\x00\x00"
        _tcp_exchange(target, port, [_tpkt(x224)])
    raise ExpectedRejection("RDP negotiation refused (no security protocol offered)")


EXECUTORS = {
    "iot-telnet": iot_telnet,
    "s7": s7,
    "bacnet": bacnet,
    "enip": enip,
    "atg": atg,
    "snmp": snmp,
    "redis": redis,
    "sip": sip,
    "tftp": tftp,
    "vnc": vnc,
    "rdp": rdp,
}
PORTS = {
    "iot-telnet": 23,
    "s7": 102,
    "bacnet": 47808,
    "enip": 44818,
    "atg": 10001,
    "snmp": 161,
    "redis": 6379,
    "sip": 5060,
    "tftp": 69,
    "vnc": 5900,
    "rdp": 3389,
}
UDP = frozenset({"bacnet", "snmp", "sip", "tftp"})
# honeypot.type stamped by each plugin (plugin.name).
HONEYPOT_TYPES = {"iot-telnet": "telnet", "s7": "s7comm"} | {s: s for s in EXECUTORS if s not in {"iot-telnet", "s7"}}
