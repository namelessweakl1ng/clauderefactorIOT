"""Sensor-side posture deception: fake lockout + fail-open cache behaviour."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

import common.hardening as posture  # noqa: E402
from camera.persona import CameraPersona  # noqa: E402
from iot_service.persona import IoTServicePersona  # noqa: E402
from mqtt.persona import MQTTPersona  # noqa: E402
from router.persona import RouterPersona  # noqa: E402


def request(persona, path="/login", method="POST", body="username=admin&password=admin", source_ip="192.168.50.20"):
    details = persona.parse(f"{method} {path} HTTP/1.1\r\nHost: h\r\n\r\n{body}".encode())
    details["source_ip"] = source_ip
    return persona.response(details)


def status(response):
    return int(response.split(b" ", 2)[1])


def teardown_function():
    posture._apply({})


def test_normal_posture_leaves_login_unchanged():
    posture._apply({})
    response = request(CameraPersona())
    # admin/admin is the valid pair -> normal flow issues a redirect, not a lockout.
    assert status(response) in (302, 303, 401) or b"session=" in response
    assert b"temporarily locked" not in response.lower()


def test_locked_source_gets_fake_lockout_on_camera_and_router():
    posture._apply({"192.168.50.20": "locked"})
    camera = request(CameraPersona())
    router = request(RouterPersona())
    assert status(camera) == 403 and b"temporarily locked" in camera.lower()
    assert status(router) == 403 and b"temporarily locked" in router.lower()
    # Deception must not reveal the honeypot.
    for response in (camera, router):
        assert all(word not in response.lower() for word in (b"trapsig", b"honeypot", b"decoy"))


def test_locked_source_gets_lockout_on_iot_and_mqtt():
    posture._apply({"192.168.50.20": "locked"})
    iot = IoTServicePersona()
    iot_details = iot.parse(b"AUTH admin admin\n")
    iot_details["source_ip"] = "192.168.50.20"
    assert b"LOCKED" in iot.response(iot_details)

    mqtt = MQTTPersona()
    connect = b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04test"
    mqtt_details = mqtt.parse(connect)
    mqtt_details["source_ip"] = "192.168.50.20"
    # Locked -> "not authorized" CONNACK (return code 0x05) instead of 0x00.
    assert mqtt.response(mqtt_details) == b"\x20\x02\x00\x05"
    # A normal source still gets a successful CONNACK.
    normal = mqtt.parse(connect)
    normal["source_ip"] = "203.0.113.7"
    assert mqtt.response(normal) == b"\x20\x02\x00\x00"


def test_other_sources_are_unaffected_when_one_ip_is_locked():
    posture._apply({"192.168.50.20": "locked"})
    response = request(CameraPersona(), source_ip="192.168.50.33")
    assert b"temporarily locked" not in response.lower()


def test_posture_for_defaults_to_normal_and_poller_is_noop_without_url(monkeypatch):
    posture._apply({})
    assert posture.posture_for("203.0.113.5") == "normal"
    monkeypatch.delenv("POSTURE_URL", raising=False)
    monkeypatch.delenv("BACKEND_URL", raising=False)
    # No backend configured -> poller does not start, returns its stop event.
    stop = posture.start_posture_poller()
    assert stop is not None
