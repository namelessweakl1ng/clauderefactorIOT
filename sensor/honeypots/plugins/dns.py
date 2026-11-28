"""Authoritative-only DNS responder for the device's fictional zone (UDP).

Never recursive (RA=0, out-of-zone → REFUSED), never answers ANY (RFC 8482 →
REFUSED here), and supports a CHAOS ``version.bind`` fingerprint only when a
version string is configured. Answers are single A/TXT records, so replies stay
within the runtime's amplification cap. Only the first question is parsed and
compression pointers in the question are rejected (bounded parsing).
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

from common.plugin import PluginConfigError, ProtocolPlugin, Reply, register

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
QCLASSES = {1: "IN", 3: "CH", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSError(ValueError):
    pass


def parse_query(data: bytes) -> dict[str, Any]:
    if len(data) < 12:
        raise DNSError("short header")
    ident, flags, qdcount = struct.unpack("!HHH", data[:6])
    if flags & 0x8000:
        raise DNSError("not a query")
    if qdcount < 1:
        raise DNSError("no question")
    index, labels = 12, []
    while True:
        if index >= len(data):
            raise DNSError("truncated name")
        length = data[index]
        if length & 0xC0:
            raise DNSError("compression in question")
        index += 1
        if length == 0:
            break
        if length > 63 or index + length > len(data) or len(labels) >= 32:
            raise DNSError("invalid label")
        labels.append(data[index : index + length].decode("ascii", "replace").lower())
        index += length
    if index + 4 > len(data):
        raise DNSError("truncated question")
    qtype, qclass = struct.unpack("!HH", data[index : index + 4])
    return {
        "id": ident,
        "opcode": (flags >> 11) & 0xF,
        "recursion_desired": bool(flags & 0x0100),
        "qname": ".".join(labels),
        "qtype": QTYPES.get(qtype, str(qtype)),
        "qtype_code": qtype,
        "qclass": QCLASSES.get(qclass, str(qclass)),
        "qclass_code": qclass,
        "question": data[12 : index + 4],
    }


def _response(query: dict[str, Any], rcode: int, answer: bytes = b"", aa: bool = True) -> bytes:
    flags = 0x8000 | (query["opcode"] << 11) | (0x0400 if aa else 0) | (0x0100 if query["recursion_desired"] else 0) | rcode
    return struct.pack("!HHHHHH", query["id"], flags, 1, 1 if answer else 0, 0, 0) + query["question"] + answer


def _rr(qtype: int, qclass: int, rdata: bytes, ttl: int = 300) -> bytes:
    return b"\xc0\x0c" + struct.pack("!HHIH", qtype, qclass, ttl, len(rdata)) + rdata


@register
class DNSPlugin(ProtocolPlugin):
    name = "dns"
    protocol = "dns"
    transport = "udp"
    default_port = 5353

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        known = {"zone", "records", "version"}
        if set(options) - known:
            raise PluginConfigError(f"dns: unknown options {sorted(set(options) - known)}")
        zone = str(options.get("zone", "lan")).lower().strip(".")
        records = options.get("records", {})
        if not isinstance(records, dict) or len(records) > 64:
            raise PluginConfigError("dns: records must be a table of name = IPv4 (≤64)")
        clean = {}
        for name, address in records.items():
            try:
                clean[str(name).lower().strip(".")] = str(ipaddress.IPv4Address(address))
            except (ipaddress.AddressValueError, ValueError) as exc:
                raise PluginConfigError(f"dns: record {name!r} must map to an IPv4 address") from exc
        version = options.get("version")
        if version is not None and (not isinstance(version, str) or len(version) > 64):
            raise PluginConfigError("dns: version must be a string ≤64 chars")
        return {"zone": zone, "records": clean, "version": version}

    def datagram(self, data: bytes, client: tuple[str, int]) -> Reply:
        try:
            query = parse_query(data)
        except DNSError as exc:
            return Reply(
                events=[{"category": "network", "action": "malformed", "outcome": "failure", "summary": f"dns malformed: {exc}", "dns": {"error": str(exc)}}]
            )
        zone, records = self.options["zone"], self.options["records"]
        name = query["qname"]
        answer, aa = b"", True
        if query["opcode"] != 0:
            rcode = 4
        elif query["qclass_code"] == 3 and name in {"version.bind", "version.server"} and query["qtype_code"] == 16:
            if self.options["version"]:
                text = self.options["version"].encode()[:64]
                rcode, answer = 0, _rr(16, 3, bytes([len(text)]) + text, 0)
            else:
                rcode = 5
        elif query["qtype_code"] == 255 or query["qclass_code"] != 1:
            rcode = 5
        elif name == zone or name.endswith("." + zone):
            if name in records and query["qtype_code"] == 1:
                rcode, answer = 0, _rr(1, 1, ipaddress.IPv4Address(records[name]).packed)
            elif name in records:
                rcode = 0  # name exists, no data of this type
            else:
                rcode = 3
        else:
            rcode, aa = 5, False  # never recursive
        details = {key: value for key, value in query.items() if key not in {"question", "qtype_code", "qclass_code"}}
        details["rcode"] = RCODES.get(rcode, str(rcode))
        event = {
            "category": "network",
            "action": "dns_query",
            "outcome": "success" if rcode == 0 else "failure",
            "summary": f"dns {query['qtype']} {name} -> {details['rcode']}",
            "dns": details,
        }
        return Reply(_response(query, rcode, answer, aa), [event])
