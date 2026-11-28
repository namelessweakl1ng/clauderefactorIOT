"""SSDP (UPnP 1.1 discovery) responder over UDP.

Answers ``M-SEARCH`` with ``MAN: "ssdp:discover"`` for ``ssdp:all``,
``upnp:rootdevice``, the device's own type, or its UUID, pointing ``LOCATION`` at
an HTTP description served by an ``http-device`` service of the same persona.
``NOTIFY`` and everything else are logged without reply. The reply is ~300
bytes, inside the runtime's amplification cap, and the runtime rate-limits it.
"""

from __future__ import annotations

import uuid
from typing import Any

from common.plugin import PluginConfigError, ProtocolPlugin, Reply, option, register


def parse_ssdp(data: bytes) -> dict[str, Any]:
    text = data.decode("latin-1", "replace")
    lines = text.split("\r\n")
    start = lines[0].split()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return {
        "method": (start[0].upper() if start else "")[:16],
        "target": start[1][:64] if len(start) > 1 else None,
        "st": headers.get("st", "")[:128] or None,
        "man": headers.get("man", "")[:64] or None,
        "mx": headers.get("mx", "")[:8] or None,
        "user_agent": headers.get("user-agent", "")[:128] or None,
    }


@register
class SSDPPlugin(ProtocolPlugin):
    name = "ssdp"
    protocol = "ssdp"
    transport = "udp"
    default_port = 1900

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        known = {"device_urn", "location_host", "location_port", "location_path", "server"}
        if set(options) - known:
            raise PluginConfigError(f"ssdp: unknown options {sorted(set(options) - known)}")
        port = option(options, "location_port", int, 49152, "ssdp")
        if not 1 <= port <= 65535:
            raise PluginConfigError("ssdp: location_port must be 1..65535")
        return {
            "device_urn": str(options.get("device_urn", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"))[:120],
            "location_host": str(options.get("location_host", "${SENSOR_IP}"))[:64],
            "location_port": port,
            "location_path": str(options.get("location_path", "/rootDesc.xml"))[:64],
            "server": str(options.get("server", "Linux/3.14 UPnP/1.1 MiniUPnPd/2.1"))[:120],
        }

    def datagram(self, data: bytes, client: tuple[str, int]) -> Reply:
        import os

        request = parse_ssdp(data)
        options = self.options
        device_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{self.persona.persona_id}.trapsig.invalid"))
        targets = {"ssdp:all", "upnp:rootdevice", options["device_urn"], f"uuid:{device_uuid}"}
        respond = request["method"] == "M-SEARCH" and (request["man"] or "").strip('"') == "ssdp:discover" and request["st"] in targets
        event = {
            "category": "network",
            "action": f"ssdp_{request['method'].lower().replace('-', '_') or 'unknown'}",
            "outcome": "success" if respond else "unknown",
            "summary": f"ssdp {request['method']} st={request['st']}",
            "ssdp": {key: value for key, value in request.items() if key != "user_agent"},
            "http": {"user_agent": request["user_agent"]} if request["user_agent"] else None,
        }
        if not respond:
            return Reply(events=[event])
        host = options["location_host"].replace("${SENSOR_IP}", os.getenv("SENSOR_IP", "0.0.0.0"))
        st = request["st"]
        usn = f"uuid:{device_uuid}" + ("" if st == f"uuid:{device_uuid}" else f"::{st}")
        reply = (
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\n"
            f"LOCATION: http://{host}:{options['location_port']}{options['location_path']}\r\n"
            f"SERVER: {options['server']}\r\nST: {st}\r\nUSN: {usn}\r\n\r\n"
        ).encode()
        return Reply(reply, [event])
