"""Behavioural tests for the learned detection policy.

These assert *properties* appropriate to a learned system -- clear-cut cases
classify correctly, every detection stays explainable -- rather than exact
integer rule boundaries (which would just smuggle the old fixed-threshold rule
back in through the test). The final test is the important one: it demonstrates
the system *adapting*, by retraining on examples the bootstrap policy gets wrong
and showing the retrained policy then gets them right.
"""

import pytest

from backend.app.services.detector import SUPPORTED_DETECTION_TYPES, detect
from backend.app.services.ml.bootstrap import DETECTION_TYPES, bootstrap_policy
from backend.app.services.ml.features import feature_vector
from backend.app.services.ml.training import TrainingExample, train


def make(events, services=None, commands=None, urls=None):
    return {
        "session_id": "SES-one",
        "source_ip": "192.168.50.20",
        "end_time": "2026-01-01T00:00:00Z",
        "event_ids": [e["event"]["id"] for e in events],
        "events": events,
        "services_touched": services or ["cowrie"],
        "commands": commands or [],
        "urls": urls or [],
    }


def ev(i, category="network", outcome="unknown", protocol="ssh", auth=None, action="observe", service=None, mqtt=None):
    return {
        "event": {"id": str(i), "category": category, "outcome": outcome, "action": action},
        "network": {"protocol": protocol},
        "service": {"name": service or ("mqtt" if protocol == "mqtt" else "cowrie")},
        **({"authentication": auth} if auth else {}),
        **({"mqtt": mqtt} if mqtt else {}),
    }


def kinds(session):
    return {item["type"] for item in detect(session)}


def test_supported_detection_types_cover_every_head_and_rule_type():
    from backend.app.services.detection.rules import default_ruleset

    # Every learned head, every generating rule type and the anomaly type are
    # valid scenario expectations; nothing else is.
    assert SUPPORTED_DETECTION_TYPES == frozenset(DETECTION_TYPES) | default_ruleset().detection_types | {"ANOMALOUS_BEHAVIOUR"}
    assert set(bootstrap_policy().detection_types) == set(DETECTION_TYPES)


@pytest.mark.parametrize(
    "session,kind",
    [
        (make([ev(i, "authentication", "failure") for i in range(24)]), "BRUTE_FORCE"),
        (make([ev(1, "authentication", "failure", auth={"username": "admin", "password": "admin"})]), "DEFAULT_CREDENTIALS"),
        (make([ev(1)], urls=["/a", "/b", "/c", "/d", "/e"]), "WEB_ENUMERATION"),
        (make([ev(1, "process", action="exec")], commands=["id", "uname -a"]), "COMMAND_INTERACTION"),
        (
            make(
                [ev(1, protocol="mqtt", mqtt={"operation": "subscribe"}), ev(2, protocol="mqtt", mqtt={"operation": "publish"})],
                services=["mqtt"],
            ),
            "MQTT_PROBING",
        ),
        (make([ev(1)], services=["camera", "router", "mqtt", "iot-service"]), "MULTI_SERVICE_ACTIVITY"),
        (
            make([ev(i, protocol="tcp", service="iot-service") for i in range(5)], services=["iot-service"]),
            "RECONNAISSANCE",
        ),
    ],
)
def test_clearcut_cases_classify_correctly_with_high_confidence(session, kind):
    detection = next(d for d in detect(session) if d["type"] == kind)
    assert detection["confidence"] >= 0.6


def test_every_fired_detection_is_explainable():
    session = make([ev(i, "authentication", "failure") for i in range(20)])
    detections = detect(session)
    assert detections
    for detection in detections:
        assert detection["reason"]
        assert detection["evidence_event_ids"]
        assert 0.0 <= detection["confidence"] <= 1.0
        assert detection["policy_version"]
        assert detection["severity"] in {"low", "medium", "high", "critical"}


def test_quiet_sessions_do_not_fire_brute_force():
    assert "BRUTE_FORCE" not in kinds(make([ev(1, "authentication", "failure")]))
    assert "BRUTE_FORCE" not in kinds(make([ev(1, "authentication", "success")]))


def test_single_service_bruteforce_does_not_trip_multi_service_or_multi_stage():
    types = kinds(make([ev(i, "authentication", "failure") for i in range(6)]))
    assert "BRUTE_FORCE" in types
    assert "MULTI_SERVICE_ACTIVITY" not in types
    assert "MULTI_STAGE_ATTACK" not in types


def test_detections_are_idempotent_by_session_and_type():
    session = make([ev(i, "authentication", "failure") for i in range(20)])
    first = {d["detection_id"] for d in detect(session)}
    second = {d["detection_id"] for d in detect(session)}
    assert first == second


def test_batch_retraining_adapts_to_examples_the_bootstrap_gets_wrong():
    """The core proof of adaptation: a stealthy 3-failure brute force.

    The bootstrap policy, like the old fixed rule, does not treat 3 failed logins
    as a brute force. We log a batch that labels that pattern BRUTE_FORCE, retrain
    (warm-started from the bootstrap weights), and show the retrained policy now
    fires on it -- without any code change to the detector.
    """
    stealthy = make([ev(i, "authentication", "failure") for i in range(3)])
    assert "BRUTE_FORCE" not in kinds(stealthy)  # bootstrap gets this "wrong" by our new ground truth

    # A small logged batch: the stealthy pattern is BRUTE_FORCE; truly quiet
    # sessions are not. Only the BRUTE_FORCE head is labeled per example.
    positives = [TrainingExample(vector=feature_vector(stealthy), labels={"BRUTE_FORCE": 1}, source="batch") for _ in range(8)]
    negatives = [
        TrainingExample(vector=feature_vector(make([ev(0, "authentication", "failure")])), labels={"BRUTE_FORCE": 0}, source="batch")
        for _ in range(8)
    ]

    retrained = train(
        positives + negatives,
        DETECTION_TYPES,
        epochs=300,
        learning_rate=0.5,
        warm_start=bootstrap_policy(),
        policy_version="test-adapted",
    )

    adapted = {d["type"] for d in detect(stealthy, policy=retrained)}
    assert "BRUTE_FORCE" in adapted
    # Adaptation is targeted: a single failed login still does not fire.
    assert "BRUTE_FORCE" not in {d["type"] for d in detect(make([ev(0, "authentication", "failure")]), policy=retrained)}


def test_per_ip_threshold_scaling_increases_sensitivity():
    """The hardening layer can lower the firing bar for a suspicious IP."""
    borderline = make([ev(i, "authentication", "failure") for i in range(4)])
    baseline = {d["type"] for d in detect(borderline)}
    sensitised = {d["type"] for d in detect(borderline, threshold_scale=0.4)}
    assert baseline <= sensitised
