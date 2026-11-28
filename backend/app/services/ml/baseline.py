"""Frozen pre-rework rule baseline -- for OFFLINE comparison only.

This reproduces the old fixed-threshold rule engine as a pure predictor so the
learned policy can be measured against the baseline it replaced (a legitimate and
expected research comparison). It is deliberately kept out of the live detection
path: ``detector.detect`` never calls this, so there is still no rule-based
decision logic deciding what fires in production -- this exists purely so
``tools/evaluate_detector.py`` can report "learned vs. rules vs. trivial".
"""

from typing import Any

from .features import FEATURE_NAMES, raw_feature_map

_INDEX = {name: position for position, name in enumerate(FEATURE_NAMES)}

# The historical fixed thresholds, frozen as the baseline (do not tune these;
# they are a fixed reference point, not a live knob).
_BRUTE_FORCE = 5
_WEB_ENUMERATION = 4
_MULTI_SERVICE = 3
_IOT_RECON = 3
_MQTT_MIN_EVENTS = 2


def rule_baseline_types(session: dict[str, Any]) -> set[str]:
    """Return the detection types the old rule engine would have fired."""
    return _fire(raw_feature_map(session))


def rule_baseline_types_from_vector(vector: list[float]) -> set[str]:
    """Same baseline, evaluated from a feature vector.

    The count features the baseline uses are stored raw in the vector (only the
    wide-range features are log1p-scaled), so this is exact -- it lets the policy
    and the baseline be scored from the same examples with no session needed.
    """
    return _fire({name: vector[_INDEX[name]] for name in FEATURE_NAMES})


def _fire(f: dict[str, float]) -> set[str]:
    fired: set[str] = set()
    if f["auth_failures"] >= _BRUTE_FORCE:
        fired.add("BRUTE_FORCE")
    if f["weak_credential_hits"] >= 1:
        fired.add("DEFAULT_CREDENTIALS")
    if f["distinct_urls"] >= _WEB_ENUMERATION:
        fired.add("WEB_ENUMERATION")
    if f["command_count"] >= 1:
        fired.add("COMMAND_INTERACTION")
    if f["mqtt_event_count"] >= _MQTT_MIN_EVENTS or f["mqtt_active_operation"] >= 1:
        fired.add("MQTT_PROBING")
    if f["distinct_services"] >= _MULTI_SERVICE:
        fired.add("MULTI_SERVICE_ACTIVITY")
    if f["iot_probe_count"] >= _IOT_RECON:
        fired.add("RECONNAISSANCE")
    if f["auth_failures"] >= 1 and (f["distinct_urls"] >= 1 or f["command_count"] >= 1) and f["distinct_services"] >= 2:
        fired.add("MULTI_STAGE_ATTACK")
    return fired
