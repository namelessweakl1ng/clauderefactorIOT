"""Community ID flow hashing, version 1 (stdlib only).

Specification: https://github.com/corelight/community-id-spec. Zeek emits the
same value (``policy/protocols/conn/community-id-logging``), so a honeypot
interaction and the passively observed network flow that carried it can be
joined on an exact key.

Inside a container the socket's local address is the container IP and the bound
port may differ from the published host port, so callers pass the sensor's
*external* address and *published* port -- the tuple Zeek sees on the wire.
"""

import base64
import hashlib
import ipaddress
import struct

PROTOCOLS = {"icmp": 1, "tcp": 6, "udp": 17, "sctp": 132}


def community_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, transport: str, seed: int = 0) -> str | None:
    """Return ``"1:<base64 sha1>"`` or ``None`` when inputs are not a valid IP flow."""
    proto = PROTOCOLS.get(str(transport).lower())
    if proto is None:
        return None
    try:
        source = ipaddress.ip_address(src_ip)
        destination = ipaddress.ip_address(dst_ip)
    except ValueError:
        return None
    if source.version != destination.version:
        return None
    src, dst = source.packed, destination.packed
    sport, dport = int(src_port), int(dst_port)
    # Order endpoints so both directions hash identically.
    if (src, sport) > (dst, dport):
        src, dst, sport, dport = dst, src, dport, sport
    data = struct.pack("!H", seed) + src + dst + struct.pack("!BB", proto, 0) + struct.pack("!HH", sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode("ascii")  # noqa: S324 - mandated by the spec
