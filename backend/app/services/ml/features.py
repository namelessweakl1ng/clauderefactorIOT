"""Deterministic session -> feature-vector transform for the learned policy.

The feature vector is computed from the *same* session shape that
``sessionizer.reconstruct_sessions()`` produces while ``events`` is still
attached (before ``processor.py`` strips it for storage), so that training and
live inference see identical inputs with no train/serve skew. For offline
retraining the sessions are re-derived from raw ``trapsig-events-*`` the same
way, never from the stripped ``trapsig-sessions`` documents.

Count-like features are compressed with ``log1p`` (diminishing returns, keeps the
logistic inputs bounded); rates and binary flags are passed through as-is. The
ordering of :data:`FEATURE_NAMES` is the schema contract: it is serialized with
every trained policy generation so old generations stay interpretable.
"""

from math import log1p
from typing import Any

from .known_weak_credentials import is_known_weak

# Ordered feature schema. Append-only: never reorder or delete, or stored
# policy weights would misalign with live features. Bump FEATURE_SCHEMA_VERSION
# whenever this list changes.
FEATURE_NAMES: tuple[str, ...] = (
    "duration",
    "event_count",
    "auth_attempts",
    "auth_failures",
    "auth_failure_rate",
    "weak_credential_hits",
    "distinct_urls",
    "command_count",
    "distinct_commands",
    "mqtt_event_count",
    "mqtt_active_operation",
    "distinct_services",
    "distinct_protocols",
    "iot_probe_count",
    "prior_detection_count",
    # ---- schema 2: protocol-generic behaviour (ICS, control, exploit, staging) ----
    "ics_write_count",
    "ics_identify_count",
    "ics_read_targets",
    "control_message_count",
    "discovery_count",
    "exploit_path_hits",
    "download_command_hits",
    "auth_success_count",
    "stream_paths",
    "upload_attempts",
)
FEATURE_SCHEMA_VERSION = "2"

# Protocol namespaces whose events carry ``write`` / ``identify`` flags (see the
# sensor plugins). Keeping the features protocol-generic means a new ICS plugin
# feeds the learned heads without touching this module.
ICS_NAMESPACES = ("modbus", "s7", "bacnet", "enip", "atg")
EXPLOIT_PATH_MARKERS = (
    "/hnap1",
    "/gponform",
    "/boaform",
    "/cgi-bin/",
    "/setup.cgi",
    "/shell",
    "/tmunblock.cgi",
    "/goform/",
    "/picsdesc.xml",
    "/ctrlt/deviceupgrade",
    "/.env",
    "/.git/",
    "/wp-config.php",
    "../",
    "%2e%2e",
)
DOWNLOAD_MARKERS = ("wget ", "curl ", "tftp ", "ftpget ", "chmod +x", "chmod 777")
DISCOVERY_PATHS = (".well-known/core", "/rootdesc.xml", "/description.xml")

_MQTT_ACTIVE_OPERATIONS = {"subscribe", "publish", "unsubscribe", "ping"}

# Human-readable phrasing per feature, used to build detection reasons.
_FEATURE_PHRASING: dict[str, str] = {
    "duration": "a long interaction window",
    "event_count": "a high interaction volume",
    "auth_attempts": "repeated authentication attempts",
    "auth_failures": "{value:.0f} authentication failures",
    "auth_failure_rate": "a high authentication-failure rate",
    "weak_credential_hits": "{value:.0f} known default-credential attempt(s)",
    "distinct_urls": "{value:.0f} distinct web paths requested",
    "command_count": "{value:.0f} command interaction(s)",
    "distinct_commands": "a varied command set",
    "mqtt_event_count": "{value:.0f} MQTT operation(s)",
    "mqtt_active_operation": "active MQTT subscribe/publish behavior",
    "distinct_services": "activity spread across {value:.0f} services",
    "distinct_protocols": "{value:.0f} distinct protocols",
    "iot_probe_count": "{value:.0f} IoT probe interaction(s)",
    "prior_detection_count": "prior recent detections for this source",
    "ics_write_count": "{value:.0f} write(s) to industrial process state",
    "ics_identify_count": "{value:.0f} industrial device-identification request(s)",
    "ics_read_targets": "{value:.0f} distinct industrial points read",
    "control_message_count": "{value:.0f} device control message(s)",
    "discovery_count": "{value:.0f} service-discovery probe(s)",
    "exploit_path_hits": "{value:.0f} known exploit/secret path request(s)",
    "download_command_hits": "{value:.0f} payload download/staging attempt(s)",
    "auth_success_count": "{value:.0f} successful login(s)",
    "stream_paths": "{value:.0f} distinct stream paths probed",
    "upload_attempts": "{value:.0f} file upload attempt(s)",
}

# Only the wide-range features are log1p-compressed (for gradient stability).
# Small discrete counts stay raw so that adjacent integers remain well separated
# and the logistic boundary at a specific count (e.g. >=3 services) is crisp
# rather than a coin flip exactly on the threshold.
_LOG_FEATURES = {"duration", "event_count"}


def _events(session: dict[str, Any]) -> list[dict[str, Any]]:
    return session.get("events") or []


def _raw_feature_values(session: dict[str, Any]) -> dict[str, float]:
    """Compute un-scaled feature values, derived from events with session fallbacks."""
    events = _events(session)

    auth_events = [e for e in events if e.get("event", {}).get("category") == "authentication"]
    auth_attempts = session.get("authentication_attempts")
    if auth_attempts is None:
        auth_attempts = len(auth_events)
    auth_failures = session.get("failed_authentication_attempts")
    if auth_failures is None:
        auth_failures = sum(e.get("event", {}).get("outcome") == "failure" for e in auth_events)

    weak_hits = sum(1 for e in events if is_known_weak(e.get("authentication", {}).get("username"), e.get("authentication", {}).get("password")))

    urls = session.get("urls") or [e.get("url", {}).get("path") for e in events if e.get("url", {}).get("path")]
    distinct_urls = len({u for u in urls if u})

    commands = session.get("commands") or [e.get("process", {}).get("command_line") for e in events if e.get("process", {}).get("command_line")]
    commands = [c for c in commands if c]

    mqtt_events = [e for e in events if e.get("network", {}).get("protocol") == "mqtt"]
    mqtt_operations = {e.get("mqtt", {}).get("operation") for e in mqtt_events}
    mqtt_active = 1.0 if mqtt_operations.intersection(_MQTT_ACTIVE_OPERATIONS) else 0.0

    services = session.get("services_touched")
    if services is None:
        services = {e.get("service", {}).get("name") for e in events}
    distinct_services = len({s for s in services if s})

    protocols = session.get("protocols")
    if protocols is None:
        protocols = {e.get("network", {}).get("protocol") for e in events}
    distinct_protocols = len({p for p in protocols if p})

    iot_probes = sum(1 for e in events if e.get("service", {}).get("name") == "iot-service" and e.get("network", {}).get("protocol") == "tcp")

    event_count = session.get("event_count")
    if event_count is None:
        event_count = len(events)

    v2 = _schema2_values(events, commands)

    return {
        "duration": float(session.get("duration") or 0.0),
        "event_count": float(event_count),
        "auth_attempts": float(auth_attempts),
        "auth_failures": float(auth_failures),
        "auth_failure_rate": (float(auth_failures) / float(auth_attempts)) if auth_attempts else 0.0,
        "weak_credential_hits": float(weak_hits),
        "distinct_urls": float(distinct_urls),
        "command_count": float(len(commands)),
        "distinct_commands": float(len(set(commands))),
        "mqtt_event_count": float(len(mqtt_events)),
        "mqtt_active_operation": mqtt_active,
        "distinct_services": float(distinct_services),
        "distinct_protocols": float(distinct_protocols),
        "iot_probe_count": float(iot_probes),
        "prior_detection_count": float(session.get("prior_detection_count") or 0.0),
        **v2,
    }


def _ns(event: dict[str, Any], name: str) -> dict[str, Any]:
    value = event.get(name)
    return value if isinstance(value, dict) else {}


def _schema2_values(events: list[dict[str, Any]], commands: list[str]) -> dict[str, float]:
    writes = identify = control = discovery = exploit = download = success = uploads = 0
    read_targets: set[tuple[str, str]] = set()
    streams: set[str] = set()
    for e in events:
        for name in ICS_NAMESPACES:
            ns = _ns(e, name)
            if not ns:
                continue
            if ns.get("write"):
                writes += 1
            elif name == "modbus" and ns.get("function_code") in (43, 17) or ns.get("identify"):
                identify += 1
            else:
                target = ns.get("address", ns.get("object", ns.get("item")))
                if target is not None:
                    read_targets.add((name, str(target)))
        coap = _ns(e, "coap")
        if coap.get("state_change"):
            writes += 1
            control += 1
        mqtt = _ns(e, "mqtt")
        if mqtt.get("operation") == "publish":
            control += 1
        if _ns(e, "redis").get("write"):
            control += 1
        path = str(_ns(e, "url").get("path") or coap.get("uri_path") or "").lower()
        if any(marker in path for marker in EXPLOIT_PATH_MARKERS) or _ns(e, "redis").get("exploit"):
            exploit += 1
        if (
            any(marker in path for marker in DISCOVERY_PATHS)
            or _ns(e, "ssdp").get("method") == "M-SEARCH"
            or _ns(e, "dns").get("qtype") == "ANY"
            or str(_ns(e, "dns").get("qname") or "").endswith("version.bind")
            or _ns(e, "snmp").get("pdu") in ("get-next", "get-bulk")
            or _ns(e, "sip").get("method") == "OPTIONS"
        ):
            discovery += 1
        if _ns(e, "ftp").get("command") in ("STOR", "APPE", "STOU") or _ns(e, "tftp").get("opcode") == "WRQ":
            uploads += 1
        if (e.get("event") or {}).get("category") == "authentication" and (e.get("event") or {}).get("outcome") == "success":
            success += 1
        rtsp_path = _ns(e, "rtsp").get("path")
        if rtsp_path:
            streams.add(str(rtsp_path))
    download = sum(any(marker in c.lower() for marker in DOWNLOAD_MARKERS) for c in commands) + uploads
    return {
        "ics_write_count": float(writes),
        "ics_identify_count": float(identify),
        "ics_read_targets": float(len(read_targets)),
        "control_message_count": float(control),
        "discovery_count": float(discovery),
        "exploit_path_hits": float(exploit),
        "download_command_hits": float(download),
        "auth_success_count": float(success),
        "stream_paths": float(len(streams)),
        "upload_attempts": float(uploads),
    }


def _scale(name: str, value: float) -> float:
    return log1p(max(value, 0.0)) if name in _LOG_FEATURES else value


def feature_vector(session: dict[str, Any]) -> list[float]:
    """Return the scaled feature vector in :data:`FEATURE_NAMES` order."""
    raw = _raw_feature_values(session)
    return [_scale(name, raw[name]) for name in FEATURE_NAMES]


def raw_feature_map(session: dict[str, Any]) -> dict[str, float]:
    """Return the un-scaled feature values keyed by name (for explanations)."""
    return _raw_feature_values(session)


def describe_feature(name: str, raw_value: float) -> str:
    """Human-readable phrase describing one feature's observed value."""
    template = _FEATURE_PHRASING.get(name, name.replace("_", " "))
    return template.format(value=raw_value)
