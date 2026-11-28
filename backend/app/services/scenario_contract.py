"""Non-secret execution-success rules shared by catalog and controlled runner."""

from typing import Any

OT_IT_SERVICES = frozenset({"s7", "bacnet", "enip", "atg", "snmp", "redis", "sip", "tftp", "vnc", "rdp"})


def allowed_step_statuses(step: dict[str, Any]) -> frozenset[str]:
    """Return statuses proving the intended action for one manifest step."""
    service = step.get("service")
    if service == "ssh":
        return frozenset({"completed"}) if step.get("command") or step.get("commands") else frozenset({"completed", "rejected"})
    if service == "iot-telnet":
        return frozenset({"completed"}) if step.get("commands") else frozenset({"completed", "rejected"})
    if service in {"camera", "http", "router", "web", "modbus", "coap", "rtsp", "ftp", "ssdp", "dns"} | OT_IT_SERVICES:
        # A protocol-level refusal (exception, 4.xx, 401, 530, REFUSED, withheld
        # UDP reply) still proves the bounded action reached the decoy.
        return frozenset({"completed", "rejected"})
    if service in {"telnet", "iot", "mqtt"}:
        return frozenset({"completed"})
    raise ValueError(f"unknown scenario service: {service!r}")
