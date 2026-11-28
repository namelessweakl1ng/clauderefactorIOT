"""Every persona-targeting scenario, executed by the real runner against the real
persona runtime on local sockets, must produce its expected detection; every
control must produce none. This is the closed loop: attack -> sensor ->
normalizer -> sessions -> hybrid detector, with no mocks in between.
"""

from pathlib import Path

import pytest
import yaml

from attacks.runner import run as runner
from attacks.runner.inprocess import InProcessLab
from backend.app.services.detector import detect
from backend.app.services.sessionizer import reconstruct_sessions

ROOT = Path(__file__).parents[2]
PERSONA_SERVICES = {"modbus", "coap", "rtsp", "ftp", "ssdp", "dns", "web", "mqtt", "router", "camera"} | {
    "iot-telnet", "s7", "bacnet", "enip", "atg", "snmp", "redis", "sip", "tftp", "vnc", "rdp"}


def scenarios():
    out = []
    for path in sorted((ROOT / "attacks/scenarios").glob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        if doc.get("models") or {s["service"] for s in doc["steps"]} <= PERSONA_SERVICES - {"mqtt", "router", "camera"}:
            if any(step["service"] in {"ssh", "telnet", "iot"} for step in doc["steps"]):
                continue  # Cowrie is a third-party container, not runnable here
            out.append(doc)
    return out


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    """Every persona on 127.0.0.1 with remapped ports."""
    running = InProcessLab(tmp_path_factory.mktemp("persona-logs")).start()
    yield running
    running.stop()


def run_scenario(doc, lab, monkeypatch=None, effects=(), decision_id=None):
    statuses, normalized = lab.run(doc, effects=effects, decision_id=decision_id)
    sessions = reconstruct_sessions(normalized)
    kinds = {d["type"] for s in sessions for d in detect(s)}
    return statuses, normalized, kinds


@pytest.mark.parametrize("doc", scenarios(), ids=lambda d: d["id"])
def test_scenario_produces_expected_outcome(doc, lab):
    statuses, events, kinds = run_scenario(doc, lab)
    from backend.app.services.scenario_contract import allowed_step_statuses

    for step, status in zip(doc["steps"], statuses, strict=True):
        assert status in allowed_step_statuses(step), f"{doc['id']}: step {step['service']} ended {status}"
    assert events, f"{doc['id']} produced no telemetry"
    if doc["trial_kind"] == "attack":
        assert doc["expected_detection"] in kinds, f"{doc['id']}: expected {doc['expected_detection']}, got {sorted(kinds)}"
    else:
        assert not kinds, f"control {doc['id']} produced {sorted(kinds)}"


def test_new_scenarios_cover_every_persona_protocol_and_new_detection_type():
    docs = scenarios()
    services = {step["service"] for doc in docs for step in doc["steps"]}
    assert {"modbus", "coap", "rtsp", "ftp", "ssdp", "dns", "web", "mqtt"} <= services
    expected = {doc["expected_detection"] for doc in docs if doc["trial_kind"] == "attack"}
    assert {
        "ICS_WRITE",
        "ICS_RECONNAISSANCE",
        "UNAUTHORIZED_COMMAND",
        "MALWARE_DOWNLOAD",
        "MULTI_STAGE_ATTACK",
        "BRUTE_FORCE",
        "DEFAULT_CREDENTIALS",
        "RECONNAISSANCE",
    } <= expected
    assert sum(doc["trial_kind"] == "control" for doc in docs) >= 4


def test_runner_refuses_unbounded_steps():
    from attacks.runner import protocols

    with pytest.raises(ValueError):
        protocols.modbus_requests({"sweep": {"start": 0, "stop": 1000, "step": 1}})
    with pytest.raises(ValueError):
        runner.ssh_campaign("192.168.50.10", {"credentials": [["a", "b"]] * 65})


@pytest.mark.parametrize(
    "scenario_id,effects",
    [
        ("camera-rtsp-default-creds", ["deny_auth"]),
        ("ics-setpoint-tamper", ["read_only"]),
        ("building-actuator-tamper", ["read_only"]),
        ("plc-firmware-implant", ["deny_auth"]),
        ("dvr-telnet-mirai-dropper", ["deny_auth"]),
        ("s7-plc-stop", ["read_only"]),
        ("bacnet-setpoint-override", ["read_only"]),
        ("enip-drive-parameter-write", ["read_only"]),
        ("atg-tank-relabel", ["read_only"]),
        ("snmp-printer-reconfigure", ["deny_auth"]),
        ("redis-ssh-key-implant", ["read_only"]),
    ],
)
def test_rl_hardening_changes_the_attacker_outcome(scenario_id, effects, lab):
    """Same attack, same personas: unhardened the attacker succeeds; with the agent's
    chosen effect enforced, harm drops to zero and the events record the hardening."""
    from backend.app.services.hardening import score_outcome

    doc = yaml.safe_load((ROOT / "attacks/scenarios" / f"{scenario_id}.yaml").read_text())
    _, open_events, _ = run_scenario(doc, lab)
    _, hardened_events, _ = run_scenario(doc, lab, effects=tuple(effects), decision_id="HRD-test")
    before, after = score_outcome(open_events), score_outcome(hardened_events)
    assert before["harm_events"] > 0, f"{scenario_id} should succeed against an unhardened decoy"
    assert after["harm_events"] == 0 and after["engaged"] == 1.0
    assert after["reward"] > before["reward"]
    assert all(e.get("hardening", {}).get("decision_id") == "HRD-test" for e in hardened_events)
