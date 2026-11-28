"""CoAP server emulation (RFC 7252) with RFC 6690 resource discovery.

GET on a configured resource → 2.05 Content; ``/.well-known/core`` → link-format
listing; PUT/POST → 2.04 Changed (nothing changes) or 4.01 when ``read_only``;
DELETE → 4.05; unknown path → 4.04. CON requests get a piggy-backed ACK, NON
requests a NON response. Malformed datagrams are logged and not answered.
Block-wise transfer and Observe are intentionally unsupported (bounded replies).
"""

from __future__ import annotations

import random
import struct
from typing import Any

from common.plugin import PluginConfigError, ProtocolPlugin, Reply, option, register

TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
METHODS = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE"}
URI_PATH, CONTENT_FORMAT, URI_QUERY = 11, 12, 15


class CoAPError(ValueError):
    pass


def _option_value(data: bytes, index: int, nibble: int) -> tuple[int, int]:
    if nibble < 13:
        return nibble, index
    if nibble == 13:
        if index >= len(data):
            raise CoAPError("truncated option")
        return data[index] + 13, index + 1
    if nibble == 14:
        if index + 1 >= len(data):
            raise CoAPError("truncated option")
        return struct.unpack("!H", data[index : index + 2])[0] + 269, index + 2
    raise CoAPError("reserved option nibble")


def parse_message(data: bytes) -> dict[str, Any]:
    if len(data) < 4:
        raise CoAPError("short header")
    first, code, message_id = data[0], data[1], struct.unpack("!H", data[2:4])[0]
    version, mtype, tkl = first >> 6, (first >> 4) & 0x3, first & 0xF
    if version != 1:
        raise CoAPError("unsupported version")
    if tkl > 8 or len(data) < 4 + tkl:
        raise CoAPError("invalid token length")
    token = data[4 : 4 + tkl]
    index, number = 4 + tkl, 0
    options: list[tuple[int, bytes]] = []
    payload = b""
    while index < len(data):
        if data[index] == 0xFF:
            payload = data[index + 1 :]
            if not payload:
                raise CoAPError("payload marker without payload")
            break
        delta, length = data[index] >> 4, data[index] & 0xF
        index += 1
        delta, index = _option_value(data, index, delta)
        length, index = _option_value(data, index, length)
        number += delta
        if index + length > len(data) or len(options) >= 32:
            raise CoAPError("option overflow")
        options.append((number, data[index : index + length]))
        index += length
    path = "/" + "/".join(value.decode("utf-8", "replace") for num, value in options if num == URI_PATH)
    query = "&".join(value.decode("utf-8", "replace") for num, value in options if num == URI_QUERY)
    content_format = next((int.from_bytes(value, "big") for num, value in options if num == CONTENT_FORMAT), None)
    return {
        "version": version,
        "type": TYPES[mtype],
        "type_code": mtype,
        "code": f"{code >> 5}.{code & 0x1F:02d}",
        "code_raw": code,
        "method": METHODS.get(code) if code >> 5 == 0 else None,
        "message_id": message_id,
        "token": token,
        "token_length": tkl,
        "uri_path": path,
        "uri_query": query or None,
        "content_format": content_format,
        "payload_length": len(payload),
        "option_count": len(options),
    }


def _encode_option(delta: int, value: bytes) -> bytes:
    def nibble(n: int) -> tuple[int, bytes]:
        if n < 13:
            return n, b""
        if n < 269:
            return 13, bytes([n - 13])
        return 14, struct.pack("!H", n - 269)

    d, dext = nibble(delta)
    length, lext = nibble(len(value))
    return bytes([(d << 4) | length]) + dext + lext + value


def build_response(request: dict[str, Any], code: tuple[int, int], payload: bytes = b"", content_format: int | None = None) -> bytes:
    mtype = 2 if request["type_code"] == 0 else 1
    message_id = request["message_id"] if mtype == 2 else random.randint(0, 0xFFFF)
    token = request["token"]
    header = bytes([(1 << 6) | (mtype << 4) | len(token), (code[0] << 5) | code[1]]) + struct.pack("!H", message_id) + token
    options = b""
    if content_format is not None:
        value = b"" if content_format == 0 else content_format.to_bytes((content_format.bit_length() + 7) // 8, "big")
        options = _encode_option(CONTENT_FORMAT, value)
    return header + options + (b"\xff" + payload if payload else b"")


@register
class CoAPPlugin(ProtocolPlugin):
    name = "coap"
    protocol = "coap"
    transport = "udp"
    default_port = 5683
    hardening_aware = True
    interaction = "low"

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        known = {"resources", "read_only"}
        if set(options) - known:
            raise PluginConfigError(f"coap: unknown options {sorted(set(options) - known)}")
        resources = options.get("resources", {"/sensors/temperature": "21.5", "/sensors/humidity": "41"})
        if not isinstance(resources, dict) or not resources or len(resources) > 64:
            raise PluginConfigError("coap: resources must be a table of 1-64 path = value entries")
        for path, value in resources.items():
            if not (isinstance(path, str) and path.startswith("/") and len(path) <= 128 and isinstance(value, str) and len(value) <= 256):
                raise PluginConfigError("coap: resource paths must start with '/' and values be strings ≤256 chars")
        return {"resources": dict(resources), "read_only": option(options, "read_only", bool, False, "coap")}

    def datagram(self, data: bytes, client: tuple[str, int], hardening: frozenset[str] = frozenset()) -> Reply:
        try:
            request = parse_message(data)
        except CoAPError as exc:
            return Reply(
                events=[
                    {
                        "category": "network",
                        "action": "malformed",
                        "outcome": "failure",
                        "summary": f"coap malformed: {exc}",
                        "coap": {"error": str(exc), "length": len(data)},
                    }
                ]
            )
        resources = self.options["resources"]
        method = request["method"]
        path = request["uri_path"]
        if request["type"] in {"ACK", "RST"} or (method is None and request["code_raw"] == 0):
            code, payload, fmt = None, b"", None  # empty/ping: no reply
        elif method == "GET" and path == "/.well-known/core":
            links = ",".join(f'<{p}>;rt="{self.persona.device_type}";if="sensor"' for p in sorted(resources))
            code, payload, fmt = (2, 5), links.encode(), 40
        elif method == "GET" and path in resources:
            code, payload, fmt = (2, 5), resources[path].encode(), 0
        elif method in {"PUT", "POST", "DELETE"} and "read_only" in hardening:
            code, payload, fmt = (4, 3), b"", None  # RL hardening: 4.03 Forbidden
        elif method in {"PUT", "POST"}:
            code, payload, fmt = ((4, 1) if self.options["read_only"] else (2, 4)), b"", None
        elif method == "DELETE":
            code, payload, fmt = (4, 5), b"", None
        elif method is None:
            code, payload, fmt = (4, 5), b"", None
        else:
            code, payload, fmt = (4, 4), b"", None
        event_details = {key: value for key, value in request.items() if key not in {"token", "code_raw", "type_code"}}
        if code is not None:
            event_details["response_code"] = f"{code[0]}.{code[1]:02d}"
        state_change = method in {"PUT", "POST", "DELETE"}
        event = {
            "category": "network",
            "action": f"coap_{(method or request['type']).lower()}",
            "outcome": "success" if code and code[0] == 2 else ("failure" if code else "unknown"),
            "summary": f"coap {method or request['type']} {path}",
            "coap": {**event_details, "state_change": state_change},
        }
        reply = build_response(request, code, payload, fmt) if code else b""
        return Reply(reply, [event])
