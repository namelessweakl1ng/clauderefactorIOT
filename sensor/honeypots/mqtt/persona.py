"""Bounded MQTT 3.1.1 honeypot persona."""

from common.hardening import LOCKED, connection_delay, posture_for

from mqtt.protocol import parse_packet

# CONNACK: connection refused, not authorized (0x05) -- the believable "locked"
# response that tarpits a locked source without revealing real state.
_CONNACK_NOT_AUTHORIZED = b"\x20\x02\x00\x05"


class MQTTPersona:
    def parse(self, data: bytes) -> dict:
        return parse_packet(data)

    def enrich(self, event: dict, details: dict) -> None:
        event["mqtt"] = {key: value for key, value in details.items() if key != "source_ip"}

    def response(self, details: dict) -> bytes:
        # Posture-driven deception (per source IP): bounded delay for a suspicious
        # source, and a "not authorized" CONNACK for a locked one. No effect under
        # normal posture, so the unit tests are unchanged.
        level = posture_for(details.get("source_ip", ""))
        connection_delay(level)
        if details.get("malformed"):
            return b""
        operation = details.get("operation")
        if level == LOCKED and operation == "connect":
            return _CONNACK_NOT_AUTHORIZED
        if operation == "connect":
            return b"\x20\x02\x00\x00"
        if operation == "ping":
            return b"\xd0\x00"
        if operation == "subscribe":
            packet_id = details["packet_id"].to_bytes(2, "big")
            return b"\x90\x03" + packet_id + b"\x00"
        if operation == "publish" and details.get("qos") == 1 and details.get("packet_id"):
            return b"\x40\x02" + details["packet_id"].to_bytes(2, "big")
        return b""
