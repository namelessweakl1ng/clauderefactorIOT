"""Realistic attack toolkit: safety (single validated target) + summary contract.

No live traffic -- network calls are stubbed. These lock in that every script
refuses a target outside LAB_SUBNET before doing anything, and that each emits a
runner-compatible summary carrying its ground-truth ``expected_detection``.
"""

import contextlib
import socket

import pytest

from attacks.realistic import credential_stuffing, http_fuzzing, iot_fuzzing, low_and_slow, mqtt_probing, service_probe

MODULES = [credential_stuffing, http_fuzzing, iot_fuzzing, low_and_slow, mqtt_probing, service_probe]
VALID_TARGET = "192.168.50.10"


@pytest.fixture(autouse=True)
def lab_subnet(monkeypatch):
    monkeypatch.setenv("LAB_SUBNET", "192.168.50.0/24")


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_every_script_declares_a_ground_truth_label(module):
    assert module.EXPECTED_DETECTION in {
        "BRUTE_FORCE",
        "WEB_ENUMERATION",
        "RECONNAISSANCE",
        "MQTT_PROBING",
        "DEFAULT_CREDENTIALS",
        "COMMAND_INTERACTION",
    }


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_out_of_subnet_target_is_refused_before_any_traffic(module, monkeypatch):
    # Make any accidental network use explode, proving validation happens first.
    def explode(*args, **kwargs):
        raise AssertionError("network call attempted for an invalid target")

    monkeypatch.setattr(socket, "create_connection", explode)
    with pytest.raises(ValueError):
        module.run("10.0.0.5")
    with pytest.raises(ValueError):
        module.run("127.0.0.1")


def _silent_socket(monkeypatch):
    class Dummy:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def sendall(self, *_):
            return None

        def recv(self, *_):
            return b""

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Dummy())


def test_credential_stuffing_summary_is_runner_compatible(monkeypatch):
    monkeypatch.setattr(credential_stuffing, "ssh_login", lambda target, step: None)
    monkeypatch.setattr(credential_stuffing, "http_request", lambda target, service, step: None)
    summary = credential_stuffing.run(VALID_TARGET, services=("ssh",), attempts=5, workers=4, jitter=0)
    assert summary["target"] == VALID_TARGET
    assert summary["expected_detection"] == "BRUTE_FORCE"
    assert summary["run_id"].startswith("RUN-")
    assert summary["step_count"] == len(summary["steps"]) == 5
    assert all({"step", "service", "started_at", "ended_at", "status"} <= set(s) for s in summary["steps"])


def test_service_probe_reports_open_and_closed_ports(monkeypatch):
    opened = {"camera"}

    @contextlib.contextmanager
    def fake_conn(address, timeout=2):
        _, port = address
        if port == 8081:
            yield object()
        else:
            raise OSError("closed")

    monkeypatch.setattr(socket, "create_connection", fake_conn)
    summary = service_probe.run(VALID_TARGET, services=["camera", "router"], jitter=0)
    assert summary["expected_detection"] == "RECONNAISSANCE"
    statuses = {s["service"]: s["status"] for s in summary["steps"]}
    assert statuses["camera"] == "completed" and statuses["router"] == "rejected"
    assert opened  # sanity: fixture used


def test_mqtt_and_iot_scripts_emit_bounded_steps(monkeypatch):
    _silent_socket(monkeypatch)
    mqtt = mqtt_probing.run(VALID_TARGET, burst=6, jitter=0)
    iot = iot_fuzzing.run(VALID_TARGET, count=6, jitter=0)
    assert mqtt["expected_detection"] == "MQTT_PROBING" and mqtt["step_count"] == 6
    assert iot["expected_detection"] == "RECONNAISSANCE" and iot["step_count"] == 6
