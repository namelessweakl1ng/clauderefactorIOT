"""Hybrid, explainable detection over reconstructed sessions.

Three engines can contribute (see ``docs/adr/0004-multi-engine-detection.md``):

* ``rule``    -- Sigma-style rules in ``backend/app/rules`` (exact evidence events,
                 author-asserted ATT&CK tags, author-assigned confidence prior);
* ``ml``      -- the learned multi-label linear policy (``services/ml``), whose
                 explanation is its top per-feature contributions ``weight × value``;
* ``anomaly`` -- an optional isolation forest over the same feature vector
                 (``services/detection/anomaly.py``), reported as ``ANOMALOUS_BEHAVIOUR``.

Output is one detection per ``(session, type)`` -- the ID scheme is unchanged, so
experiment correlation and history remain valid -- with ``signals[]`` recording
every engine that fired, ``fired_by`` listing them, and an ``attack`` mapping.

``DETECTION_MODE`` selects ``hybrid`` (default), ``rules`` or ``ml``; the
comparison framework evaluates each mode offline on identical folds.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from .detection.attack import TYPE_DEFAULTS, describe
from .detection.rules import RuleSet, default_ruleset
from .ml.bootstrap import DETECTION_TYPES, bootstrap_policy
from .ml.features import FEATURE_SCHEMA_VERSION, describe_feature, feature_vector, raw_feature_map
from .ml.policy import LinearPolicy

MODES = ("hybrid", "rules", "ml")
ANOMALY_TYPE = "ANOMALOUS_BEHAVIOUR"
_ENGINE_ORDER = {"rule": 0, "ml": 1, "anomaly": 2}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_LEVEL_TO_SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

DETECTOR_VERSION = f"policy-fs{FEATURE_SCHEMA_VERSION}+{default_ruleset().version}"
SUPPORTED_DETECTION_TYPES = frozenset(DETECTION_TYPES) | default_ruleset().detection_types | {ANOMALY_TYPE}

# Process-local caches refreshed by the processor each cycle.
_active_policy: LinearPolicy | None = None
_rule_states: dict[str, bool] = {}
_anomaly_model: Any = None


def set_active_policy(policy: LinearPolicy | None) -> None:
    global _active_policy
    _active_policy = policy


def get_active_policy() -> LinearPolicy:
    return _active_policy if _active_policy is not None else bootstrap_policy()


def set_rule_states(states: dict[str, bool] | None) -> None:
    global _rule_states
    _rule_states = dict(states or {})


def get_rule_states() -> dict[str, bool]:
    return dict(_rule_states)


def set_anomaly_model(model: Any) -> None:
    global _anomaly_model
    _anomaly_model = model


def get_anomaly_model() -> Any:
    return _anomaly_model


def detection_mode() -> str:
    mode = os.getenv("DETECTION_MODE", "hybrid").lower()
    return mode if mode in MODES else "hybrid"


def _ml_signals(session: dict[str, Any], policy: LinearPolicy, thresholds: dict[str, float] | None, threshold_scale: float) -> list[dict[str, Any]]:
    fragments = policy.evaluate(session, thresholds=thresholds, threshold_scale=threshold_scale)
    if not fragments:
        return []
    vector = feature_vector(session)
    raw = raw_feature_map(session)
    signals = []
    for fragment in fragments:
        top = [
            {"feature": name, "value": raw.get(name, 0.0), "contribution": round(contribution, 6), "description": describe_feature(name, raw.get(name, 0.0))}
            for name, contribution in policy.contributions(fragment["type"], vector)[:5]
            if contribution != 0
        ]
        signals.append(
            {
                "engine": "ml",
                "type": fragment["type"],
                "confidence": fragment["confidence"],
                "confidence_calibrated": policy.is_calibrated(fragment["type"]),
                "severity": fragment["severity"],
                "reason": fragment["reason"],
                "version": fragment["policy_version"],
                "effective_threshold": fragment["effective_threshold"],
                "features": top,
                "evidence_event_ids": list(session.get("event_ids", [])),
            }
        )
    return signals


def _rule_signals(session: dict[str, Any], ruleset: RuleSet, states: dict[str, bool]) -> list[dict[str, Any]]:
    events = session.get("events") or []
    if not events:
        return []
    signals = []
    for match in ruleset.evaluate(events, enabled=states):
        rule = match.rule
        signals.append(
            {
                "engine": "rule",
                "type": rule.detection_type,
                "confidence": rule.confidence,
                "confidence_calibrated": False,
                "severity": _LEVEL_TO_SEVERITY[rule.level],
                "level": rule.level,
                "reason": match.reason(),
                "version": ruleset.version,
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_title": rule.title,
                "rule_version": rule.version,
                "rule_status": rule.status,
                "observed": match.observed,
                "attack_techniques": rule.attack_techniques,
                "evidence_event_ids": match.evidence_event_ids,
            }
        )
    return signals


def _anomaly_signals(session: dict[str, Any], model: Any) -> list[dict[str, Any]]:
    if model is None:
        return []
    result = model.score_session(session)
    if not result["anomalous"]:
        return []
    return [
        {
            "engine": "anomaly",
            "type": ANOMALY_TYPE,
            "confidence": result["score"],
            "confidence_calibrated": False,
            "severity": "medium" if result["score"] < 0.75 else "high",
            "reason": result["reason"],
            "version": model.model_version,
            "anomaly_score": result["score"],
            "threshold": model.threshold,
            "features": result["features"],
            "evidence_event_ids": list(session.get("event_ids", [])),
        }
    ]


def _merge(session: dict[str, Any], kind: str, signals: list[dict[str, Any]], detected_at: str) -> dict[str, Any]:
    signals = sorted(signals, key=lambda s: (_ENGINE_ORDER[s["engine"]], -float(s["confidence"])))
    primary = max(signals, key=lambda s: (float(s["confidence"]), -_ENGINE_ORDER[s["engine"]]))
    severity = max((s["severity"] for s in signals), key=lambda value: _SEVERITY_RANK.get(value, 0))
    rule_signals = [s for s in signals if s["engine"] == "rule"]
    if rule_signals:
        evidence: list[str] = []
        for signal in rule_signals:
            evidence.extend(item for item in signal["evidence_event_ids"] if item not in evidence)
    else:
        evidence = list(session.get("event_ids", []))
    techniques: list[str] = []
    for signal in rule_signals:
        techniques.extend(signal.get("attack_techniques") or [])
    mapping = "rule-tag" if techniques else "type-default"
    if not techniques:
        techniques = list(TYPE_DEFAULTS.get(kind, ()))
    others = len(signals) - 1
    reason = primary["reason"] + (f" Corroborated by {others} other signal(s)." if others else "")
    ml = next((s for s in signals if s["engine"] == "ml"), None)
    end_time = session.get("end_time")
    key = f"{session['session_id']}:{kind}"
    return {
        "detection_id": "DET-" + sha256(key.encode()).hexdigest()[:16],
        "session_id": session["session_id"],
        "source_ip": session.get("source_ip"),
        "type": kind,
        "severity": severity,
        "confidence": round(float(primary["confidence"]), 6),
        "confidence_calibrated": bool(primary.get("confidence_calibrated")),
        "policy_version": primary["version"],
        "effective_threshold": ml["effective_threshold"] if ml else None,
        "timestamp": end_time,
        "evidence_end_time": end_time,
        "detected_at": detected_at,
        "reason": reason,
        "evidence_event_ids": evidence,
        # Back-compat: the identifier of the logic that produced the primary signal.
        "rule_id": primary.get("rule_id") or primary["version"],
        "fired_by": sorted({s["engine"] for s in signals}, key=_ENGINE_ORDER.__getitem__),
        "signals": signals,
        "attack": describe(techniques, mapping),
        "services": list(session.get("services_touched") or []),
    }


def detect(
    session: dict[str, Any],
    *,
    policy: LinearPolicy | None = None,
    thresholds: dict[str, float] | None = None,
    threshold_scale: float = 1.0,
    ruleset: RuleSet | None = None,
    rule_states: dict[str, bool] | None = None,
    anomaly_model: Any = None,
    mode: str | None = None,
) -> list[dict[str, Any]]:
    """Return merged detections for ``session``.

    ``threshold_scale`` (<1 lowers the bar) and per-type ``thresholds`` tune the
    *learned* heads only; rules are deterministic and are not posture-scaled.
    """
    mode = mode or detection_mode()
    signals: list[dict[str, Any]] = []
    if mode in {"hybrid", "ml"}:
        signals.extend(_ml_signals(session, policy or get_active_policy(), thresholds, threshold_scale))
    if mode in {"hybrid", "rules"}:
        signals.extend(_rule_signals(session, ruleset or default_ruleset(), _rule_states if rule_states is None else rule_states))
    if mode == "hybrid":
        signals.extend(_anomaly_signals(session, anomaly_model if anomaly_model is not None else _anomaly_model))
    by_type: dict[str, list[dict[str, Any]]] = {}
    for signal in signals:
        by_type.setdefault(signal["type"], []).append(signal)
    detected_at = datetime.now(timezone.utc).isoformat()
    return [_merge(session, kind, items, detected_at) for kind, items in sorted(by_type.items())]
