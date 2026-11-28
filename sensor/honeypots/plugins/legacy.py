"""Adapters exposing the original four personas as plugins (behaviour unchanged).

Each adapter performs exactly what the legacy single-request handler did: frame
one message with the original bounded reader, ``parse`` → ``enrich`` → ``response``,
then close. The legacy event fields are mapped onto plugin *details*, so a
persona can combine, e.g., the AsterView web UI with an RTSP service.
"""

from __future__ import annotations

import socket
from typing import Any, Callable

from common.plugin import Conversation, FrameError, ProtocolPlugin, Reply, register
from common.server import HTTPRequestReadError, ProtocolReadError, http_error_response, read_http_request, read_iot_command, read_mqtt_frame
from common.telemetry import base_event

_FIELDS = ("authentication", "url", "http", "iot", "mqtt")


class _LegacyConversation(Conversation):
    def __init__(self, plugin: "_LegacyPlugin", client: tuple[str, int]) -> None:
        super().__init__(plugin, client)
        self.error_reply: bytes | None = None

    def read(self, connection: socket.socket) -> bytes | None:
        if self.state.get("done"):
            return None
        try:
            return self.plugin.reader(connection)  # type: ignore[attr-defined]
        except HTTPRequestReadError as error:
            self.error_reply = http_error_response(error)
            self.state["done"] = True
            connection.sendall(self.error_reply)
            return None
        except ProtocolReadError as exc:
            raise FrameError(str(exc)) from exc

    def handle(self, message: bytes) -> Reply:
        self.state["done"] = True
        plugin: _LegacyPlugin = self.plugin  # type: ignore[assignment]
        details = plugin.persona_impl.parse(message)
        if isinstance(details, dict):
            details.setdefault("source_ip", self.client[0])
        event = base_event(plugin.legacy_service, plugin.legacy_protocol, 0, self.client, details, bool(message))
        plugin.persona_impl.enrich(event, details)
        mapped: dict[str, Any] = {
            "category": event.get("category"),
            "type": event.get("type"),
            "action": event.get("action"),
            "outcome": event.get("outcome"),
            "summary": event.get("summary"),
        }
        for key in _FIELDS:
            if isinstance(event.get(key), dict):
                mapped[key] = event[key]
        return Reply(plugin.persona_impl.response(details), [mapped], close=True)


class _LegacyPlugin(ProtocolPlugin):
    legacy_service: str
    legacy_protocol: str
    factory: Callable[[], Any]
    handles_posture = True
    max_messages_limit = 1

    def __init__(self, persona, options=None) -> None:
        super().__init__(persona, options)
        self.persona_impl = type(self).factory()

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return _LegacyConversation(self, client)


def _camera():
    from camera.persona import CameraPersona

    return CameraPersona()


def _router():
    from router.persona import RouterPersona

    return RouterPersona()


def _iot():
    from iot_service.persona import IoTServicePersona

    return IoTServicePersona()


def _mqtt():
    from mqtt.persona import MQTTPersona

    return MQTTPersona()


@register
class LegacyCamera(_LegacyPlugin):
    name, protocol, default_port = "asterview-camera-http", "http", 8081
    legacy_service, legacy_protocol, factory = "camera", "http", staticmethod(_camera)
    interaction = "medium"
    reader = staticmethod(read_http_request)


@register
class LegacyRouter(_LegacyPlugin):
    name, protocol, default_port = "nexora-router-http", "http", 8080
    legacy_service, legacy_protocol, factory = "router", "http", staticmethod(_router)
    interaction = "medium"
    reader = staticmethod(read_http_request)


@register
class LegacyIoT(_LegacyPlugin):
    name, protocol, default_port = "velora-vcp", "tcp", 9000
    legacy_service, legacy_protocol, factory = "iot-service", "tcp", staticmethod(_iot)
    reader = staticmethod(read_iot_command)


@register
class LegacyMQTT(_LegacyPlugin):
    name, protocol, default_port = "velora-mqtt", "mqtt", 1883
    legacy_service, legacy_protocol, factory = "mqtt", "mqtt", staticmethod(_mqtt)
    reader = staticmethod(read_mqtt_frame)
