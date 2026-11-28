"""Modbus/TCP server emulation (Modbus Application Protocol v1.1b3).

Supported: 1/2 read coils/discrete inputs, 3/4 read holding/input registers,
5/6 write single coil/register, 15/16 write multiple, 17 report server ID,
43/14 read device identification. Anything else returns exception 01. Requests
outside the configured maps return exception 02; malformed values exception 03.

Writes are applied to a **connection-local overlay** so a read-after-write within
the same connection is consistent (attackers verify writes), but nothing persists
and no process is controlled. Input registers drift deterministically so polling
looks alive. Ideas, not code, from Conpot's slave/block templates (GPL-2).
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any

from common.plugin import Conversation, FrameError, PluginConfigError, ProtocolPlugin, Reply, option, recv_exact, register

FUNCTIONS = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    17: "report_server_id",
    43: "encapsulated_interface_transport",
}
MAX_PDU = 253


def _registers(options: dict[str, Any], key: str, default: list[int]) -> list[int]:
    values = options.get(key, default)
    if (
        not isinstance(values, list)
        or not values
        or len(values) > 1024
        or not all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 0xFFFF for v in values)
    ):
        raise PluginConfigError(f"modbus: {key} must be a list of 1-1024 integers 0..65535")
    return list(values)


@register
class ModbusPlugin(ProtocolPlugin):
    name = "modbus"
    protocol = "modbus"
    default_port = 5020
    interaction = "medium"
    max_messages_limit = 512

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        known = {"unit_id", "holding_registers", "input_registers", "coils", "discrete_inputs", "server_id"}
        if set(options) - known:
            raise PluginConfigError(f"modbus: unknown options {sorted(set(options) - known)}")
        unit = option(options, "unit_id", int, 1, "modbus")
        if not 0 <= unit <= 247:
            raise PluginConfigError("modbus: unit_id must be 0..247")
        coils = option(options, "coils", int, 64, "modbus")
        discrete = option(options, "discrete_inputs", int, 32, "modbus")
        if not (1 <= coils <= 2048 and 1 <= discrete <= 2048):
            raise PluginConfigError("modbus: coils/discrete_inputs must be 1..2048")
        return {
            "unit_id": unit,
            "holding_registers": _registers(options, "holding_registers", [0] * 32),
            "input_registers": _registers(options, "input_registers", [0] * 16),
            "coils": coils,
            "discrete_inputs": discrete,
            "server_id": option(options, "server_id", int, 0x42, "modbus") & 0xFF,
        }

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        connection.settimeout(self.read_timeout)
        try:
            first = connection.recv(1)
        except socket.timeout as exc:
            raise FrameError("read timeout") from exc
        if not first:
            return None
        header = first + recv_exact(connection, 6, self.read_timeout)
        _, protocol_id, length = struct.unpack("!HHH", header[:6])
        if protocol_id != 0:
            raise FrameError("non-Modbus protocol identifier")
        if not 2 <= length <= MAX_PDU + 1:
            raise FrameError("invalid MBAP length")
        return header + recv_exact(connection, length - 1, self.read_timeout)

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return ModbusConversation(self, client)


class ModbusConversation(Conversation):
    def __init__(self, plugin: ModbusPlugin, client: tuple[str, int]) -> None:
        super().__init__(plugin, client)
        options = plugin.options
        self.holding = list(options["holding_registers"])
        self.coils = [False] * options["coils"]
        self.discrete = [i % 3 == 0 for i in range(options["discrete_inputs"])]

    def _input_registers(self) -> list[int]:
        tick = int(time.time() // 10)
        return [(value + (tick + index) % 5) & 0xFFFF for index, value in enumerate(self.plugin.options["input_registers"])]

    def handle(self, message: bytes) -> Reply:
        transaction, _, _, unit = struct.unpack("!HHHB", message[:7])
        pdu = message[7:]
        function = pdu[0]
        details: dict[str, Any] = {"transaction_id": transaction, "unit_id": unit, "function_code": function, "function": FUNCTIONS.get(function, "unknown")}
        options = self.plugin.options
        if unit not in {options["unit_id"], 0, 255}:
            return self._exception(transaction, unit, function, 0x0B, details)
        if function in (5, 6, 15, 16, 22, 23) and "read_only" in self.hardening:
            # RL hardening: the controller is "locked in RUN mode" for this source.
            details["hardening_blocked"] = True
            return self._exception(transaction, unit, function, 0x04, details)
        try:
            body = self._dispatch(function, pdu[1:], details)
        except _ModbusException as exc:
            return self._exception(transaction, unit, function, exc.code, details)
        response = bytes([function]) + body
        details["response_length"] = len(response)
        return self._reply(transaction, unit, response, details)

    def _dispatch(self, function: int, data: bytes, details: dict[str, Any]) -> bytes:
        if function in (1, 2, 3, 4):
            if len(data) != 4:
                raise _ModbusException(3)
            address, quantity = struct.unpack("!HH", data)
            details.update(address=address, quantity=quantity)
            if function in (1, 2):
                table = self.coils if function == 1 else self.discrete
                if not 1 <= quantity <= 2000:
                    raise _ModbusException(3)
                if address + quantity > len(table):
                    raise _ModbusException(2)
                bits = table[address : address + quantity]
                packed = bytearray((quantity + 7) // 8)
                for index, bit in enumerate(bits):
                    if bit:
                        packed[index // 8] |= 1 << (index % 8)
                return bytes([len(packed)]) + bytes(packed)
            table = self.holding if function == 3 else self._input_registers()
            if not 1 <= quantity <= 125:
                raise _ModbusException(3)
            if address + quantity > len(table):
                raise _ModbusException(2)
            values = table[address : address + quantity]
            return bytes([2 * quantity]) + struct.pack(f"!{quantity}H", *values)
        if function == 5:
            if len(data) != 4:
                raise _ModbusException(3)
            address, value = struct.unpack("!HH", data)
            details.update(address=address, value=value)
            if value not in (0x0000, 0xFF00):
                raise _ModbusException(3)
            if address >= len(self.coils):
                raise _ModbusException(2)
            self.coils[address] = value == 0xFF00
            return data
        if function == 6:
            if len(data) != 4:
                raise _ModbusException(3)
            address, value = struct.unpack("!HH", data)
            details.update(address=address, value=value)
            if address >= len(self.holding):
                raise _ModbusException(2)
            self.holding[address] = value
            return data
        if function in (15, 16):
            if len(data) < 5:
                raise _ModbusException(3)
            address, quantity, count = struct.unpack("!HHB", data[:5])
            details.update(address=address, quantity=quantity)
            payload = data[5:]
            if len(payload) != count:
                raise _ModbusException(3)
            if function == 15:
                if not 1 <= quantity <= 1968 or count != (quantity + 7) // 8:
                    raise _ModbusException(3)
                if address + quantity > len(self.coils):
                    raise _ModbusException(2)
                for index in range(quantity):
                    self.coils[address + index] = bool(payload[index // 8] >> (index % 8) & 1)
            else:
                if not 1 <= quantity <= 123 or count != 2 * quantity:
                    raise _ModbusException(3)
                if address + quantity > len(self.holding):
                    raise _ModbusException(2)
                values = struct.unpack(f"!{quantity}H", payload)
                details["values"] = list(values[:16])
                self.holding[address : address + quantity] = list(values)
            return struct.pack("!HH", address, quantity)
        if function == 17:
            text = f"{self.plugin.persona.model} {self.plugin.persona.firmware}".encode()[:64]
            body = bytes([self.plugin.options["server_id"], 0xFF]) + text
            return bytes([len(body)]) + body
        if function == 43:
            if len(data) < 3 or data[0] != 0x0E:
                raise _ModbusException(1)
            read_code, object_id = data[1], data[2]
            details.update(mei_type=14, read_device_id_code=read_code, object_id=object_id)
            if read_code not in (1, 2, 3, 4):
                raise _ModbusException(3)
            persona = self.plugin.persona
            objects = [persona.vendor or "Unknown", persona.model or "Unknown", persona.firmware or "1.0"]
            start = object_id if read_code == 4 else 0
            if start > 2:
                raise _ModbusException(2)
            chosen = objects[start : start + 1] if read_code == 4 else objects
            encoded = b"".join(bytes([start + i, len(v.encode()[:64])]) + v.encode()[:64] for i, v in enumerate(chosen))
            return bytes([0x0E, read_code, 0x01, 0x00, 0x00, len(chosen)]) + encoded
        raise _ModbusException(1)

    def _exception(self, transaction: int, unit: int, function: int, code: int, details: dict[str, Any]) -> Reply:
        details["exception_code"] = code
        return self._reply(transaction, unit, bytes([function | 0x80, code]), details)

    def _reply(self, transaction: int, unit: int, pdu: bytes, details: dict[str, Any]) -> Reply:
        frame = struct.pack("!HHHB", transaction, 0, len(pdu) + 1, unit) + pdu
        write = details["function_code"] in (5, 6, 15, 16)
        event = {
            "category": "network",
            "action": details["function"],
            "outcome": "failure" if "exception_code" in details else "success",
            "summary": f"modbus {details['function']}" + (f" exception {details['exception_code']}" if "exception_code" in details else ""),
            "modbus": {**details, "write": write},
        }
        return Reply(frame, [event])


class _ModbusException(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code
