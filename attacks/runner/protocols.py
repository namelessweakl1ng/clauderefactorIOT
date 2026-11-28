"""Bounded client-side protocol actions for persona services.

Every function talks to exactly one ``target`` host (already validated inside
``LAB_SUBNET`` by the runner), on one port, with short timeouts and hard caps on
the number of requests. Nothing here scans, floods, persists, or transfers a
real payload. A protocol-level refusal (Modbus exception, CoAP 4.xx, RTSP 401,
FTP 530, DNS REFUSED, an unanswered UDP probe) raises ``ExpectedRejection``,
because the action demonstrably reached the decoy.
"""

from __future__ import annotations

import base64
import random
import socket
import struct
from typing import Any

MAX_REQUESTS_PER_STEP = 64


class ExpectedRejection(Exception):
    """The bounded action reached the service and was intentionally rejected."""


def _cap(items: list[Any]) -> list[Any]:
    if len(items) > MAX_REQUESTS_PER_STEP:
        raise ValueError(f"a step may issue at most {MAX_REQUESTS_PER_STEP} requests")
    return items


# --------------------------------------------------------------------------- #
# Modbus/TCP
# --------------------------------------------------------------------------- #

MODBUS_FUNCTIONS = {
    "read_coils": 1,
    "read_discrete_inputs": 2,
    "read_holding_registers": 3,
    "read_input_registers": 4,
    "write_single_coil": 5,
    "write_single_register": 6,
    "write_multiple_registers": 16,
    "report_server_id": 17,
    "read_device_identification": 43,
}


def modbus_pdu(request: dict[str, Any]) -> bytes:
    function = MODBUS_FUNCTIONS[request["function"]]
    address = int(request.get("address", 0))
    if function in (1, 2, 3, 4):
        return struct.pack("!BHH", function, address, int(request.get("quantity", 1)))
    if function == 5:
        return struct.pack("!BHH", function, address, 0xFF00 if request.get("value") else 0x0000)
    if function == 6:
        return struct.pack("!BHH", function, address, int(request["value"]) & 0xFFFF)
    if function == 16:
        values = [int(v) & 0xFFFF for v in request["values"]][:16]
        return struct.pack(f"!BHHB{len(values)}H", function, address, len(values), 2 * len(values), *values)
    if function == 17:
        return bytes([17])
    return bytes([0x2B, 0x0E, 0x01, 0x00])


def modbus_requests(step: dict[str, Any]) -> list[dict[str, Any]]:
    requests = list(step.get("requests") or [])
    sweep = step.get("sweep")
    if sweep:
        for address in range(int(sweep["start"]), int(sweep["stop"]), int(sweep.get("step", 1))):
            requests.append({"function": sweep.get("function", "read_holding_registers"), "address": address, "quantity": int(sweep.get("quantity", 1))})
    return _cap(requests)


def modbus(target: str, port: int, step: dict[str, Any]) -> None:
    unit = int(step.get("unit", 1))
    exceptions = 0
    requests = modbus_requests(step)
    with socket.create_connection((target, port), timeout=3) as connection:
        for transaction, request in enumerate(requests, start=1):
            pdu = modbus_pdu(request)
            connection.sendall(struct.pack("!HHHB", transaction, 0, len(pdu) + 1, unit) + pdu)
            header = connection.recv(7)
            if len(header) < 7:
                raise ExpectedRejection("modbus connection closed")
            length = struct.unpack("!H", header[4:6])[0]
            body = connection.recv(max(1, length - 1))
            if body and body[0] & 0x80:
                exceptions += 1
    if exceptions == len(requests):
        raise ExpectedRejection(f"all {exceptions} modbus requests returned exceptions")


# --------------------------------------------------------------------------- #
# CoAP (UDP)
# --------------------------------------------------------------------------- #

COAP_METHODS = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4}


def coap_message(method: str, path: str, payload: str | None = None, message_id: int | None = None) -> bytes:
    token = random.randbytes(2)
    mid = message_id if message_id is not None else random.randint(0, 0xFFFF)
    header = bytes([0x40 | len(token), COAP_METHODS[method.upper()]]) + struct.pack("!H", mid) + token
    options, previous = b"", 0
    for segment in [s for s in path.split("/") if s]:
        value = segment.encode()[:255]
        delta = 11 - previous
        if len(value) < 13:
            options += bytes([(delta << 4) | len(value)]) + value
        else:
            options += bytes([(delta << 4) | 13, len(value) - 13]) + value
        previous = 11
    body = b"\xff" + payload.encode() if payload else b""
    return header + options + body


def _udp(target: str, port: int, data: bytes) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(2)
        udp.sendto(data, (target, port))
        try:
            return udp.recvfrom(2048)[0]
        except socket.timeout:
            return None


def coap(target: str, port: int, step: dict[str, Any]) -> None:
    requests = _cap(
        list(step.get("requests") or [{"method": step.get("method", "GET"), "path": step.get("path", "/.well-known/core"), "payload": step.get("payload")}])
    )
    refused = 0
    for request in requests:
        reply = _udp(target, port, coap_message(request.get("method", "GET"), request["path"], request.get("payload")))
        if reply is None or len(reply) < 2 or reply[1] >> 5 >= 4:
            refused += 1
    if refused == len(requests):
        raise ExpectedRejection("every CoAP request was refused or unanswered")


# --------------------------------------------------------------------------- #
# RTSP
# --------------------------------------------------------------------------- #


def rtsp(target: str, port: int, step: dict[str, Any]) -> None:
    paths = _cap(list(step.get("paths") or [step.get("path", "/")]))
    method = step.get("method", "DESCRIBE").upper()
    auth = ""
    if step.get("username") is not None:
        auth = "Authorization: Basic " + base64.b64encode(f"{step['username']}:{step['password']}".encode()).decode() + "\r\n"
    statuses = []
    with socket.create_connection((target, port), timeout=3) as connection:
        for cseq, path in enumerate(paths, start=1):
            request = (
                f"{method} rtsp://{target}:{port}{path} RTSP/1.0\r\nCSeq: {cseq}\r\n"
                f"User-Agent: LibVLC/3.0.20 (LIVE555 Streaming Media v2016.11.28)\r\n{auth}\r\n"
            )
            connection.sendall(request.encode())
            reply = connection.recv(4096).decode("latin-1")
            if not reply:
                break
            statuses.append(int(reply.split()[1]) if reply.startswith("RTSP/") else 0)
    if not statuses or all(code >= 400 for code in statuses):
        raise ExpectedRejection(f"RTSP responses {sorted(set(statuses))}")


# --------------------------------------------------------------------------- #
# FTP (control channel only; the decoy never opens data connections)
# --------------------------------------------------------------------------- #


def ftp(target: str, port: int, step: dict[str, Any]) -> None:
    commands = _cap([f"USER {step.get('username', 'anonymous')}", f"PASS {step.get('password', 'guest@')}", *step.get("commands", []), "QUIT"])
    with socket.create_connection((target, port), timeout=3) as connection:
        stream = connection.makefile("rb")
        stream.readline()  # banner
        logged_in = False
        for command in commands:
            connection.sendall((command + "\r\n").encode())
            reply = stream.readline().decode("latin-1")
            while reply[3:4] == "-":  # multi-line reply
                reply = stream.readline().decode("latin-1")
            if command.startswith("PASS"):
                logged_in = reply.startswith("230")
                if not logged_in and not step.get("continue_on_failure"):
                    connection.sendall(b"QUIT\r\n")
                    raise ExpectedRejection(f"FTP login refused: {reply.strip()}")
            if not reply:
                break


# --------------------------------------------------------------------------- #
# SSDP and DNS (UDP)
# --------------------------------------------------------------------------- #


def ssdp(target: str, port: int, step: dict[str, Any]) -> None:
    targets = _cap(list(step.get("search_targets") or [step.get("st", "ssdp:all")]))
    answered = 0
    for st in targets:
        message = (
            f'M-SEARCH * HTTP/1.1\r\nHOST: {target}:{port}\r\nMAN: "ssdp:discover"\r\nMX: 1\r\n'
            f"ST: {st}\r\nUSER-AGENT: Linux/5.10 UPnP/1.1 miniupnpc/2.2\r\n\r\n"
        )
        answered += _udp(target, port, message.encode()) is not None
    if not answered:
        raise ExpectedRejection("no SSDP responses")


DNS_TYPES = {"A": 1, "TXT": 16, "AAAA": 28, "ANY": 255}
DNS_CLASSES = {"IN": 1, "CH": 3}


def dns_query(name: str, qtype: str, qclass: str = "IN") -> bytes:
    header = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.strip(".").split(".") if part) + b"\x00"
    return header + labels + struct.pack("!HH", DNS_TYPES[qtype.upper()], DNS_CLASSES[qclass.upper()])


def dns(target: str, port: int, step: dict[str, Any]) -> None:
    queries = _cap(list(step.get("queries") or [{"name": step.get("name", "version.bind"), "type": step.get("type", "TXT"), "class": step.get("class", "CH")}]))
    answered = 0
    for query in queries:
        reply = _udp(target, port, dns_query(query["name"], query.get("type", "A"), query.get("class", "IN")))
        if reply and len(reply) >= 4 and struct.unpack("!H", reply[2:4])[0] & 0xF == 0:
            answered += 1
    if not answered:
        raise ExpectedRejection("every DNS query was refused, NXDOMAIN or unanswered")
