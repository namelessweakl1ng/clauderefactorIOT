"""Hybrid merge, explanations, ATT&CK mapping, anomaly engine."""

import random

import pytest

from backend.app.services.detection.anomaly import IsolationForest, average_path_length
from backend.app.services.detection.attack import TECHNIQUES, verify_against_stix
from backend.app.services.detector import detect
from backend.app.services.ml.features import feature_vector
from backend.app.services.sessionizer import reconstruct_sessions


def event(i, seconds, **fields):
    base = {
        "@timestamp": f"2026-01-01T00:{seconds // 60:02d}:{seconds % 60:02d}Z",
        "event": {"id": f"ev-{i}", "category": "network", "outcome": "unknown", "action": "x"},
        "source": {"ip": "192.168.50.20"},
        "honeypot": {"id": "cowrie-01"},
        "service": {"name": "cowrie"},
        "network": {"protocol": "ssh"},
    }
    for key, value in fields.items():
        base[key] = {**base.get(key, {}), **value} if isinstance(value, dict) else value
    return base


def bruteforce_session(n=8, noise=2):
    events = [
        event(i, i, event={"category": "authentication", "outcome": "failure"}, authentication={"username": "root", "password": f"p{i}"}) for i in range(n)
    ]
    events += [event(100 + i, n + i, event={"category": "session", "action": "cowrie.session.connect"}) for i in range(noise)]
    return reconstruct_sessions(events)[0]


def test_hybrid_detection_records_both_engines_and_exact_rule_evidence():
    session = bruteforce_session()
    detection = next(d for d in detect(session, mode="hybrid") if d["type"] == "BRUTE_FORCE")
    assert detection["fired_by"] == ["rule", "ml"]
    engines = {s["engine"] for s in detection["signals"]}
    assert engines == {"rule", "ml"}
    # Rule evidence is exactly the failed logins, not the connect noise.
    assert set(detection["evidence_event_ids"]) == {f"ev-{i}" for i in range(8)}
    assert all(not e.startswith("ev-10") for e in detection["evidence_event_ids"])


def test_ml_signal_explains_with_feature_contributions():
    session = bruteforce_session()
    ml = next(s for d in detect(session, mode="ml") for s in d["signals"] if s["type"] == "BRUTE_FORCE")
    assert ml["features"], "learned detections must cite contributing features"
    assert {"feature", "value", "contribution", "description"} <= set(ml["features"][0])
    assert ml["confidence_calibrated"] is False


def test_rule_only_mode_uses_rule_version_and_attack_tags():
    session = bruteforce_session()
    detection = next(d for d in detect(session, mode="rules") if d["type"] == "BRUTE_FORCE")
    assert detection["fired_by"] == ["rule"]
    assert detection["policy_version"].startswith("rules-")
    techniques = {t["id"] for t in detection["attack"]}
    assert "T1110.001" in techniques
    assert all(t["mapping"] == "rule-tag" and t["known"] for t in detection["attack"])


def test_type_default_attack_mapping_for_ml_only_detection():
    session = bruteforce_session()
    detection = next(d for d in detect(session, mode="ml") if d["type"] == "BRUTE_FORCE")
    assert detection["attack"][0]["mapping"] == "type-default"


def test_detection_ids_are_mode_independent():
    session = bruteforce_session()
    ids = {mode: {d["type"]: d["detection_id"] for d in detect(session, mode=mode)} for mode in ("hybrid", "rules", "ml")}
    assert ids["hybrid"]["BRUTE_FORCE"] == ids["rules"]["BRUTE_FORCE"] == ids["ml"]["BRUTE_FORCE"]


def test_disabling_a_rule_removes_its_signal():
    from backend.app.services.detection.rules import default_ruleset

    session = bruteforce_session()
    rule_ids = {r.id for r in default_ruleset().rules.values() if r.detection_type == "BRUTE_FORCE"}
    detections = detect(session, mode="rules", rule_states={rid: False for rid in rule_ids})
    assert "BRUTE_FORCE" not in {d["type"] for d in detections}


def test_new_protocol_rules_fire_through_detect():
    events = [event(i, i, service={"name": "plc"}, network={"protocol": "modbus"}, modbus={"function_code": 6, "address": 1}) for i in range(2)]
    session = reconstruct_sessions(events)[0]
    detection = next(d for d in detect(session) if d["type"] == "ICS_WRITE")
    assert detection["severity"] == "critical"
    assert {"T0855", "T0836"} <= {t["id"] for t in detection["attack"]}


# ---- anomaly --------------------------------------------------------------- #


def _corpus(seed=1, n=200):
    rng = random.Random(seed)
    sessions = []
    for i in range(n):
        failures = rng.randint(0, 3)
        events = [event(j, j, event={"category": "authentication", "outcome": "failure"}) for j in range(failures)] or [event(0, 0)]
        sessions.append(
            {
                "session_id": f"S{i}",
                "events": events,
                "event_count": len(events),
                "duration": float(rng.randint(0, 30)),
                "services_touched": ["cowrie"],
                "protocols": ["ssh"],
            }
        )
    return sessions


def test_isolation_forest_is_deterministic_and_flags_outliers():
    vectors = [feature_vector(s) for s in _corpus()]
    first, second = IsolationForest.fit(vectors, seed=7), IsolationForest.fit(vectors, seed=7)
    assert first.model_version == second.model_version and first.threshold == second.threshold
    ordinary = vectors[0]
    outlier = list(ordinary)
    outlier[1] = 9.0  # log1p(event_count) far outside training range
    outlier[7] = 40.0  # command_count never seen
    assert first.score(outlier) > first.score(ordinary)
    assert first.score(outlier) >= first.threshold


def test_isolation_forest_round_trips_and_explains():
    model = IsolationForest.fit([feature_vector(s) for s in _corpus()], seed=3)
    restored = IsolationForest.from_document(model.to_document())
    weird = {
        "session_id": "W",
        "events": [event(0, 0)],
        "event_count": 4000,
        "duration": 9000.0,
        "commands": [f"c{i}" for i in range(30)],
        "services_touched": ["cowrie"],
    }
    assert restored.score(feature_vector(weird)) == pytest.approx(model.score(feature_vector(weird)))
    result = restored.score_session(weird)
    assert result["anomalous"] and result["features"] and "heuristic" in result["reason"]
    detection = next(d for d in detect({**weird, "event_ids": ["ev-0"]}, anomaly_model=restored) if d["type"] == "ANOMALOUS_BEHAVIOUR")
    assert detection["fired_by"] == ["anomaly"]


def test_isolation_forest_requires_minimum_data():
    with pytest.raises(ValueError):
        IsolationForest.fit([[0.0] * 15] * 3)


def test_average_path_length_matches_paper_values():
    assert average_path_length(1) == 0.0
    assert average_path_length(2) == 1.0
    assert average_path_length(256) == pytest.approx(10.244, abs=0.01)


# ---- ATT&CK verification ---------------------------------------------------- #


def test_catalogue_verification_reports_drift():
    bundle = {
        "objects": [
            {"type": "attack-pattern", "name": TECHNIQUES[t]["name"], "external_references": [{"source_name": "mitre-attack", "external_id": t}]}
            for t in TECHNIQUES
            if t != "T1046"
        ]
        + [
            {
                "type": "attack-pattern",
                "name": "Renamed",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1046"}],
                "x_mitre_deprecated": True,
            }
        ]
    }
    report = verify_against_stix([bundle])
    assert report["missing"] == []
    assert report["renamed"] == [{"id": "T1046", "catalogue": "Network Service Discovery", "stix": "Renamed"}]
    assert report["deprecated"] == ["T1046"]
