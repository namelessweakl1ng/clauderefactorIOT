"""Industrial protocol emulators: S7comm, BACnet/IP, EtherNet/IP, Guardian AST tank gauge.

Behavioural ideas from Conpot (GPL-2; no code reused). Every emulator answers
identification requests with the persona's fictional identity, applies writes to
connection-local state only, and refuses process changes when the RL agent has
set ``read_only`` for the source. Events carry ``write`` / ``identify`` flags so
rules and the learned detector treat all ICS protocols uniformly.
"""

from __future__ import annotations

import socket
import struct
from typing import Any

from common.plugin import Conversation, FrameError, PluginConfigError, ProtocolPlugin, Reply, option, recv_exact, register


def _event(namespace: str, action: str, details: dict[str, Any], outcome: str = "success") -> dict[str, Any]:
    return {"category": "network", "action": action, "outcome": outcome, "summary": f"{namespace} {action}", namespace: details}


# --------------------------------------------------------------------------- #
# S7comm over ISO-on-TCP (TPKT / COTP)
# --------------------------------------------------------------------------- #

S7_FUNCTIONS = {0xF0: "setup_communication", 0x04: "read_var", 0x05: "write_var", 0x28: "plc_control", 0x29: "plc_stop", 0x1A: "request_download"}
S7_WRITES = {0x05, 0x28, 0x29, 0x1A}


def _tpkt(payload: bytes) -> bytes:
    return struct.pack("!BBH", 3, 0, len(payload) + 4) + payload


@register
class S7Plugin(ProtocolPlugin):
    name = "s7comm"
    protocol = "s7"
    default_port = 10102
    interaction = "medium"
    max_messages_limit = 128

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"module", "serial", "plant"}:
            raise PluginConfigError("s7comm: options are module, serial, plant")
        return {
            "module": str(options.get("module", "6ES7 315-2EH14-0AB0"))[:32],
            "serial": str(options.get("serial", "S C-X4U421302009"))[:24],
            "plant": str(options.get("plant", "Mainline"))[:32],
        }

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        connection.settimeout(self.read_timeout)
        try:
            first = connection.recv(1)
        except socket.timeout as exc:
            raise FrameError("read timeout") from exc
        if not first:
            return None
        header = first + recv_exact(connection, 3, self.read_timeout)
        if header[0] != 3:
            raise FrameError("not TPKT")
        length = struct.unpack("!H", header[2:4])[0]
        if not 7 <= length <= 1024:
            raise FrameError("invalid TPKT length")
        return header + recv_exact(connection, length - 4, self.read_timeout)

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return S7Conversation(self, client)


class S7Conversation(Conversation):
    def handle(self, message: bytes) -> Reply:
        cotp = message[4:]
        pdu_type = cotp[1] if len(cotp) > 1 else 0
        if pdu_type == 0xE0:  # COTP connection request -> confirm
            confirm = bytes([0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02])
            return Reply(_tpkt(confirm), [_event("s7", "cotp_connect", {"function": "cotp_connect"})])
        if pdu_type != 0xF0 or len(cotp) < 3:
            return Reply(events=[_event("s7", "malformed", {"function": "unknown"}, "failure")], close=True)
        s7 = cotp[3:]
        if len(s7) < 10 or s7[0] != 0x32:
            return Reply(events=[_event("s7", "malformed", {"function": "not_s7"}, "failure")], close=True)
        rosctr, pdu_ref = s7[1], s7[4:6]
        param_len = struct.unpack("!H", s7[6:8])[0]
        params = s7[10 : 10 + param_len]
        if rosctr == 7:  # userdata: SZL read = identification
            szl_id = struct.unpack("!H", s7[10 + param_len + 4 : 10 + param_len + 6])[0] if len(s7) >= 10 + param_len + 6 else 0
            persona = self.plugin.persona
            text = f"{self.plugin.options['module']} {persona.model} {persona.firmware} {self.plugin.options['serial']}".encode()[:120]
            data = b"\xff\x09" + struct.pack("!H", len(text) + 4) + struct.pack("!HH", szl_id, 1) + text
            header = b"\x32\x07\x00\x00" + pdu_ref + struct.pack("!HH", 12, len(data))
            param = b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00"
            details = {"function": "szl_read", "szl_id": szl_id, "identify": True, "write": False}
            return Reply(_tpkt(b"\x02\xf0\x80" + header + param + data), [_event("s7", "szl_read", details)])
        function = params[0] if params else 0
        name = S7_FUNCTIONS.get(function, f"function_{function:#04x}")
        write = function in S7_WRITES
        details: dict[str, Any] = {"function": name, "function_code": function, "write": write, "identify": False}
        if function == 0x04 and len(params) >= 14:
            details["area"], details["address"] = params[8 + 0], struct.unpack("!H", params[12:14])[0]
        blocked = write and "read_only" in self.hardening
        if blocked:
            details["hardening_blocked"] = True
        error = b"\x00\x00" if not blocked else b"\x81\x04"  # 0x8104: context not supported (refused)
        if function == 0xF0:
            reply_params = b"\xf0\x00\x00\x01\x00\x01\x01\xe0"
            data = b""
        elif function == 0x04:
            reply_params, data = b"\x04\x01", b"\xff\x04\x00\x10\x00\x00"
        elif function == 0x05:
            reply_params, data = b"\x05\x01", (b"\xff" if not blocked else b"\x03")
        else:
            reply_params, data = bytes([function]), b""
        header = b"\x32\x03\x00\x00" + pdu_ref + struct.pack("!HH", len(reply_params), len(data)) + error
        outcome = "failure" if blocked else "success"
        return Reply(_tpkt(b"\x02\xf0\x80" + header + reply_params + data), [_event("s7", name, details, outcome)], close=function == 0x29)


# --------------------------------------------------------------------------- #
# BACnet/IP (UDP)
# --------------------------------------------------------------------------- #

BACNET_PROPERTIES = {77: "object_name", 121: "vendor_name", 70: "model_name", 44: "firmware_revision", 75: "object_identifier"}


@register
class BACnetPlugin(ProtocolPlugin):
    name = "bacnet"
    protocol = "bacnet"
    transport = "udp"
    default_port = 47808
    hardening_aware = True

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"device_instance", "vendor_id"}:
            raise PluginConfigError("bacnet: options are device_instance, vendor_id")
        instance = option(options, "device_instance", int, 2001, "bacnet")
        if not 0 <= instance < 4194303:
            raise PluginConfigError("bacnet: device_instance out of range")
        return {"device_instance": instance, "vendor_id": option(options, "vendor_id", int, 999, "bacnet") & 0xFFFF}

    def datagram(self, data: bytes, client: tuple[str, int], hardening: frozenset[str] = frozenset()) -> Reply:
        if len(data) < 6 or data[0] != 0x81:
            return Reply(events=[_event("bacnet", "malformed", {"service": "not_bvlc"}, "failure")])
        npdu = data[4:]
        control = npdu[1] if len(npdu) > 1 else 0
        offset = 2 + (0 if not control & 0x08 else 4)  # skip optional DNET fields (bounded)
        apdu = npdu[offset:]
        if not apdu:
            return Reply(events=[_event("bacnet", "malformed", {"service": "empty"}, "failure")])
        pdu_type = apdu[0] >> 4
        device = self.options["device_instance"]
        object_id = struct.pack("!I", (8 << 22) | device)
        bvlc = lambda body: b"\x81\x0a" + struct.pack("!H", len(body) + 4) + body  # noqa: E731
        if pdu_type == 1 and len(apdu) > 1 and apdu[1] == 0x08:  # Who-Is
            body = b"\x01\x00" + b"\x10\x00" + b"\xc4" + object_id + b"\x22\x05\xc4\x91\x00\x21" + bytes([self.options["vendor_id"] & 0xFF])
            return Reply(bvlc(body), [_event("bacnet", "who_is", {"service": "who-is", "identify": True, "write": False})])
        if pdu_type == 0 and len(apdu) >= 4:
            invoke, service = apdu[2], apdu[3]
            if service == 0x0C:  # ReadProperty
                # [4] context tag 0 (object id, 4 bytes), [9] context tag 1 (property id, len in low bits)
                prop = apdu[10] if len(apdu) > 10 and apdu[9] & 0xF8 == 0x18 else 0
                name = BACNET_PROPERTIES.get(prop, f"property_{prop}")
                persona = self.persona
                value = {77: persona.name, 121: persona.vendor, 70: persona.model, 44: persona.firmware}.get(prop)
                details = {"service": "read-property", "property": name, "object": "device", "identify": prop in BACNET_PROPERTIES, "write": False}
                if value is None:
                    body = b"\x01\x00" + bytes([0x50, invoke, 0x0C, 0x91, 0x02, 0x91, 0x20])  # error: property unknown
                    return Reply(bvlc(body), [_event("bacnet", "read_property", details, "failure")])
                encoded = value.encode()[:60]
                body = (
                    b"\x01\x00"
                    + bytes([0x30, invoke, 0x0C])
                    + b"\x0c"
                    + object_id
                    + bytes([0x19, prop])
                    + b"\x3e\x75"
                    + bytes([len(encoded) + 1, 0])
                    + encoded
                    + b"\x3f"
                )
                return Reply(bvlc(body), [_event("bacnet", "read_property", details)])
            if service == 0x0F:  # WriteProperty
                blocked = "read_only" in hardening
                details = {"service": "write-property", "write": True, "identify": False, "hardening_blocked": blocked}
                body = b"\x01\x00" + (bytes([0x50, invoke, 0x0F, 0x91, 0x02, 0x91, 0x28]) if blocked else bytes([0x20, invoke, 0x0F]))
                return Reply(bvlc(body), [_event("bacnet", "write_property", details, "failure" if blocked else "success")])
            return Reply(
                bvlc(b"\x01\x00" + bytes([0x50, invoke, service, 0x91, 0x05, 0x91, 0x00])),
                [_event("bacnet", "unsupported", {"service": f"service_{service}"}, "failure")],
            )
        return Reply(events=[_event("bacnet", "unhandled", {"service": f"pdu_{pdu_type}"}, "failure")])


# --------------------------------------------------------------------------- #
# EtherNet/IP encapsulation (TCP 44818)
# --------------------------------------------------------------------------- #

ENIP_COMMANDS = {
    0x63: "list_identity",
    0x04: "list_services",
    0x65: "register_session",
    0x66: "unregister_session",
    0x6F: "send_rr_data",
    0x70: "send_unit_data",
}


@register
class ENIPPlugin(ProtocolPlugin):
    name = "enip"
    protocol = "enip"
    default_port = 44818
    interaction = "low"
    max_messages_limit = 64

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"vendor_id", "device_type", "product_code", "serial"}:
            raise PluginConfigError("enip: options are vendor_id, device_type, product_code, serial")
        return {
            "vendor_id": option(options, "vendor_id", int, 1, "enip") & 0xFFFF,
            "device_type": option(options, "device_type", int, 14, "enip") & 0xFFFF,
            "product_code": option(options, "product_code", int, 55, "enip") & 0xFFFF,
            "serial": option(options, "serial", int, 0x6151F2B1, "enip") & 0xFFFFFFFF,
        }

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        connection.settimeout(self.read_timeout)
        try:
            first = connection.recv(1)
        except socket.timeout as exc:
            raise FrameError("read timeout") from exc
        if not first:
            return None
        header = first + recv_exact(connection, 23, self.read_timeout)
        length = struct.unpack("<H", header[2:4])[0]
        if length > 1024:
            raise FrameError("encapsulation too long")
        return header + (recv_exact(connection, length, self.read_timeout) if length else b"")

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return ENIPConversation(self, client)


class ENIPConversation(Conversation):
    def handle(self, message: bytes) -> Reply:
        command, _, session, _, context = struct.unpack("<HHII8s", message[:20])
        name = ENIP_COMMANDS.get(command, f"command_{command:#06x}")
        details: dict[str, Any] = {"command": name, "identify": command in (0x63, 0x04), "write": False}
        options = self.plugin.options
        if command == 0x63:
            product = (self.plugin.persona.model or "Drive").encode()[:32]
            item = (
                struct.pack("<HH", 1, 0)
                + struct.pack(">HHI8x", 2, 44818, 0)
                + struct.pack("<HHHBBHI", options["vendor_id"], options["device_type"], options["product_code"], 3, 1, 0x0030, options["serial"])
                + bytes([len(product)])
                + product
                + b"\x03"
            )
            data = struct.pack("<HHH", 1, 0x0C, len(item)) + item
        elif command == 0x65:
            session = 0x0A0B0C0D
            data = struct.pack("<HH", 1, 0)
        elif command == 0x04:
            data = struct.pack("<HHHHH16s", 1, 0x100, 20, 1, 0x0120, b"Communications\x00\x00")
        else:
            cip_service = message[40] if len(message) > 40 else 0
            details["cip_service"] = cip_service
            details["write"] = cip_service in (0x10, 0x4D, 0x53)  # set attribute / write tag
            blocked = details["write"] and "read_only" in self.state.get("hardening", frozenset())
            if blocked:
                details["hardening_blocked"] = True
            outcome = "failure" if blocked else "success"
            data = b""
            if command == 0x6F and cip_service:
                # SendRRData reply: CIP service|0x80, general status 0 or 0x0F (privilege violation).
                cip = bytes([cip_service | 0x80, 0, 0x0F if blocked else 0, 0])
                data = struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
            reply = struct.pack("<HHII8sI", command, len(data), session, 0 if command in ENIP_COMMANDS else 1, context, 0) + data
            return Reply(reply, [_event("enip", name, details, outcome)])
        reply = struct.pack("<HHII8sI", command, len(data), session, 0 if command in ENIP_COMMANDS else 1, context, 0) + data
        return Reply(reply, [_event("enip", name, details)], close=command == 0x66)


# --------------------------------------------------------------------------- #
# Guardian AST / automatic tank gauge (TCP 10001)
# --------------------------------------------------------------------------- #


@register
class ATGPlugin(ProtocolPlugin):
    name = "atg"
    protocol = "atg"
    default_port = 10001
    interaction = "low"
    max_messages_limit = 32

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        if set(options) - {"station", "tanks"}:
            raise PluginConfigError("atg: options are station, tanks")
        tanks = options.get("tanks", ["UNLEADED", "PREMIUM", "DIESEL"])
        if not isinstance(tanks, list) or not 1 <= len(tanks) <= 8:
            raise PluginConfigError("atg: tanks must be a list of 1-8 product names")
        return {"station": str(options.get("station", "FUEL STATION 22"))[:40], "tanks": [str(t)[:16] for t in tanks]}

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        connection.settimeout(self.read_timeout)
        buffer = conversation.state.setdefault("_buffer", bytearray())
        try:
            while b"\n" not in buffer and b"\r" not in buffer and len(buffer) < 64:
                chunk = connection.recv(64)
                if not chunk:
                    return bytes(buffer) if buffer else None
                buffer.extend(chunk)
        except socket.timeout as exc:
            if buffer:
                line = bytes(buffer)
                buffer.clear()
                return line
            raise FrameError("read timeout") from exc
        line = bytes(buffer)
        buffer.clear()
        return line

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return ATGConversation(self, client)


class ATGConversation(Conversation):
    def handle(self, message: bytes) -> Reply:
        command = message.replace(b"\x01", b"").strip().decode("latin-1")[:16].upper()
        options = self.plugin.options
        write = command.startswith("S6")
        details = {"command": command, "write": write, "identify": command.startswith("I2")}
        if command.startswith("I201"):
            rows = "\r\n".join(f"  {i + 1}  {name:<14} {8000 + 731 * i:>6} GAL  {52.3 + i:>5.1f} IN  {58 + i} F" for i, name in enumerate(options["tanks"]))
            body = f"I20100\r\n\r\n{options['station']}\r\n\r\nIN-TANK INVENTORY\r\n\r\nTANK PRODUCT        VOLUME   HEIGHT  TEMP\r\n{rows}\r\n"
        elif command.startswith("S6") and "read_only" in self.hardening:
            details["hardening_blocked"] = True
            body = "9999FF1B\r\n"
        elif command.startswith(("I2", "S6")):
            body = f"{command}\r\n\r\n{options['station']}\r\n"
        else:
            body = "9999FF1B\r\n"  # unrecognised function code
        outcome = "failure" if body.startswith("9999") else "success"
        return Reply(b"\x01" + body.encode() + b"\x03", [_event("atg", "command", details, outcome)])
