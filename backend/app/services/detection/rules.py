"""Sigma-inspired, session-scoped detection rules.

Format
------
A rule file holds one or more YAML documents. Two kinds of rule exist, mirroring
Sigma's split between *event rules* and *correlation rules*:

* **Event rule** -- ``detection:`` with named selections and a ``condition``.
  Selections are a mapping (all fields must match) or a list of mappings (any
  mapping matches). Field keys accept Sigma value modifiers:
  ``field|contains``, ``|startswith``, ``|endswith``, ``|re``, ``|cidr``,
  ``|gt``, ``|gte``, ``|lt``, ``|lte``, ``|exists``, ``|all``, ``|cased``.
  Plain string values are case-insensitive and support ``*``/``?`` wildcards.
  A list of values means "any of" unless ``|all`` is given.
  The condition grammar supports ``and``, ``or``, ``not``, parentheses,
  ``1 of sel*``, ``all of sel*``, ``1 of them`` and ``all of them``.

* **Correlation rule** -- ``correlation:`` referencing other rules by ``name``:
  ``event_count`` / ``value_count`` (with ``field``) and a numeric ``condition``
  over an optional sliding ``timespan`` and ``group_by``; ``temporal`` (all
  referenced rules matched within ``timespan``) and ``temporal_ordered`` (they
  matched in the listed order).

All evaluation is scoped to one reconstructed session (one source IP inside the
inactivity timeout), which is the unit the rest of TRAPSIG reasons about. Base
rules may set ``generate: false`` so they only feed correlations.

This is an independent implementation written from the public Sigma
specification; no pySigma code is used.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from ..ml.known_weak_credentials import is_known_weak

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("stable", "test", "experimental", "deprecated")
CORRELATION_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists", "all", "cased"}
_COMPARATORS = ("gt", "gte", "lt", "lte", "eq")
_TIMESPAN = re.compile(r"^(\d+)([smhd]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_TECHNIQUE_TAG = re.compile(r"attack\.t\d{4}(\.\d{3})?")
_TEST_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()


class RuleError(ValueError):
    """A rule failed validation. The message names the rule and the problem."""


# --------------------------------------------------------------------------- #
# Event access and derived enrichment
# --------------------------------------------------------------------------- #


def get_field(event: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path on a nested event; also accept flat dotted keys."""
    if path in event:
        return event[path]
    current: Any = event
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def enrich(event: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy carrying explicit derived fields under ``trapsig.derived``.

    Derived values are deliberately few and documented, so rules never depend on
    hidden logic: currently only ``known_default_credential`` (shared list with
    the attack toolkit and the ML feature of the same meaning).
    """
    auth = event.get("authentication") or {}
    derived = {"known_default_credential": is_known_weak(auth.get("username"), auth.get("password")) if auth else False}
    trapsig = dict(event.get("trapsig") or {})
    trapsig["derived"] = derived
    return {**event, "trapsig": trapsig}


# --------------------------------------------------------------------------- #
# Field matchers
# --------------------------------------------------------------------------- #


def _wildcard(pattern: str, value: str, cased: bool) -> bool:
    if not cased:
        pattern, value = pattern.lower(), value.lower()
    if "*" in pattern or "?" in pattern:
        return fnmatchcase(value, pattern)
    return pattern == value


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _match_scalar(expected: Any, actual: Any, mods: set[str], compiled: re.Pattern[str] | None) -> bool:
    if actual is None:
        return expected is None
    if expected is None:
        return False
    cased = "cased" in mods
    if "re" in mods:
        return compiled is not None and compiled.search(str(actual)) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    for comparator in ("gt", "gte", "lt", "lte"):
        if comparator in mods:
            left, right = _number(actual), _number(expected)
            if left is None or right is None:
                return False
            return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[comparator]
    if isinstance(expected, bool) or isinstance(actual, bool):
        return bool(actual) is bool(expected) and isinstance(actual, bool) and isinstance(expected, bool)
    if isinstance(expected, (int, float)):
        number = _number(actual)
        return number is not None and number == float(expected)
    text, pattern = str(actual), str(expected)
    if "contains" in mods:
        return (pattern in text) if cased else (pattern.lower() in text.lower())
    if "startswith" in mods:
        return text.startswith(pattern) if cased else text.lower().startswith(pattern.lower())
    if "endswith" in mods:
        return text.endswith(pattern) if cased else text.lower().endswith(pattern.lower())
    return _wildcard(pattern, text, cased)


@dataclass(frozen=True)
class FieldMatcher:
    path: str
    modifiers: frozenset[str]
    values: tuple[Any, ...]
    patterns: tuple[re.Pattern[str] | None, ...]

    def __call__(self, event: dict[str, Any]) -> bool:
        actual = get_field(event, self.path)
        if "exists" in self.modifiers:
            present = actual is not None and actual != "" and actual != []
            return present is bool(self.values[0])
        candidates = actual if isinstance(actual, list) else [actual]
        mods = set(self.modifiers)

        def one(index: int) -> bool:
            return any(_match_scalar(self.values[index], candidate, mods, self.patterns[index]) for candidate in candidates)

        results = (one(index) for index in range(len(self.values)))
        return all(results) if "all" in self.modifiers else any(results)


def _compile_field(rule_name: str, key: str, value: Any) -> FieldMatcher:
    path, *mods = key.split("|")
    unknown = set(mods) - MODIFIERS
    if unknown:
        raise RuleError(f"{rule_name}: unknown modifier(s) {sorted(unknown)} on {key!r}")
    if not path:
        raise RuleError(f"{rule_name}: empty field name in {key!r}")
    values = tuple(value) if isinstance(value, list) else (value,)
    if not values:
        raise RuleError(f"{rule_name}: field {key!r} has an empty value list")
    patterns: list[re.Pattern[str] | None] = []
    for item in values:
        if "re" in mods:
            try:
                patterns.append(re.compile(str(item), 0 if "cased" in mods else re.IGNORECASE))
            except re.error as exc:
                raise RuleError(f"{rule_name}: invalid regular expression {item!r}: {exc}") from exc
        else:
            patterns.append(None)
        if "cidr" in mods:
            try:
                ipaddress.ip_network(str(item), strict=False)
            except ValueError as exc:
                raise RuleError(f"{rule_name}: invalid CIDR {item!r}") from exc
    return FieldMatcher(path, frozenset(mods), values, tuple(patterns))


Selection = Callable[[dict[str, Any]], bool]


def _compile_selection(rule_name: str, name: str, body: Any) -> Selection:
    if isinstance(body, dict):
        if not body:
            raise RuleError(f"{rule_name}: selection {name!r} is empty")
        matchers = [_compile_field(rule_name, str(key), value) for key, value in body.items()]
        return lambda event: all(matcher(event) for matcher in matchers)
    if isinstance(body, list) and body and all(isinstance(item, dict) for item in body):
        alternatives = [_compile_selection(rule_name, name, item) for item in body]
        return lambda event: any(alternative(event) for alternative in alternatives)
    raise RuleError(f"{rule_name}: selection {name!r} must be a mapping or a list of mappings")


# --------------------------------------------------------------------------- #
# Condition grammar (recursive descent)
# --------------------------------------------------------------------------- #

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-]+)")


def _tokenize(rule_name: str, text: str) -> list[str]:
    tokens, position = [], 0
    text = text.strip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        if not match:
            raise RuleError(f"{rule_name}: cannot parse condition near {text[position:]!r}")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class _ConditionParser:
    def __init__(self, rule_name: str, tokens: list[str], selections: dict[str, Selection]) -> None:
        self.rule_name, self.tokens, self.selections, self.index = rule_name, tokens, selections, 0

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise RuleError(f"{self.rule_name}: condition ended unexpectedly")
        self.index += 1
        return token

    def parse(self) -> Selection:
        expression = self.parse_or()
        if self.peek() is not None:
            raise RuleError(f"{self.rule_name}: unexpected token {self.peek()!r} in condition")
        return expression

    def parse_or(self) -> Selection:
        left = self.parse_and()
        while (self.peek() or "").lower() == "or":
            self.take()
            right = self.parse_and()
            left = (lambda a, b: lambda event: a(event) or b(event))(left, right)
        return left

    def parse_and(self) -> Selection:
        left = self.parse_not()
        while (self.peek() or "").lower() == "and":
            self.take()
            right = self.parse_not()
            left = (lambda a, b: lambda event: a(event) and b(event))(left, right)
        return left

    def parse_not(self) -> Selection:
        if (self.peek() or "").lower() == "not":
            self.take()
            inner = self.parse_not()
            return lambda event: not inner(event)
        return self.parse_atom()

    def _group(self, pattern: str) -> list[Selection]:
        if pattern == "them":
            names = list(self.selections)
        else:
            names = [name for name in self.selections if fnmatchcase(name, pattern)]
        if not names:
            raise RuleError(f"{self.rule_name}: {pattern!r} matches no selection")
        return [self.selections[name] for name in names]

    def parse_atom(self) -> Selection:
        token = self.take()
        if token == "(":
            inner = self.parse_or()
            if self.take() != ")":
                raise RuleError(f"{self.rule_name}: unbalanced parentheses in condition")
            return inner
        if token.lower() in {"1", "all"} and (self.peek() or "").lower() == "of":
            self.take()
            group = self._group(self.take())
            if token == "1":
                return lambda event: any(selection(event) for selection in group)
            return lambda event: all(selection(event) for selection in group)
        if token not in self.selections:
            raise RuleError(f"{self.rule_name}: condition references unknown selection {token!r}")
        return self.selections[token]


# --------------------------------------------------------------------------- #
# Rule model
# --------------------------------------------------------------------------- #


def parse_timespan(rule_name: str, value: Any) -> float | None:
    if value is None:
        return None
    match = _TIMESPAN.match(str(value).strip())
    if not match:
        raise RuleError(f"{rule_name}: invalid timespan {value!r} (use e.g. 300, 5m, 1h)")
    return float(int(match.group(1)) * _UNITS[match.group(2)])


def _parse_comparison(rule_name: str, condition: Any) -> tuple[str, float]:
    if not isinstance(condition, dict) or len(condition) != 1:
        raise RuleError(f"{rule_name}: correlation condition must be one of {{gt|gte|lt|lte|eq: N}}")
    ((operator, threshold),) = condition.items()
    if operator not in _COMPARATORS or _number(threshold) is None:
        raise RuleError(f"{rule_name}: invalid correlation condition {condition!r}")
    return str(operator), float(threshold)


def _compare(operator: str, value: float, threshold: float) -> bool:
    return {"gt": value > threshold, "gte": value >= threshold, "lt": value < threshold, "lte": value <= threshold, "eq": value == threshold}[operator]


@dataclass
class Rule:
    name: str
    id: str
    title: str
    version: int
    status: str
    level: str
    description: str
    detection_type: str | None
    confidence: float
    tags: tuple[str, ...]
    generate: bool
    falsepositives: tuple[str, ...]
    references: tuple[str, ...]
    source_file: str
    content_sha256: str
    logsource: dict[str, Any] = field(default_factory=dict)
    matcher: Selection | None = None
    correlation: dict[str, Any] | None = None
    tests: list[dict[str, Any]] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return "correlation" if self.correlation else "event"

    @property
    def attack_techniques(self) -> list[str]:
        return ["T" + tag[8:].upper() for tag in self.tags if _TECHNIQUE_TAG.fullmatch(tag)]

    @property
    def attack_tactics(self) -> list[str]:
        return [tag[7:] for tag in self.tags if tag.startswith("attack.") and not _TECHNIQUE_TAG.fullmatch(tag)]

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "id": self.id,
            "title": self.title,
            "version": self.version,
            "status": self.status,
            "level": self.level,
            "kind": self.kind,
            "description": self.description,
            "detection_type": self.detection_type,
            "confidence": self.confidence,
            "generate": self.generate,
            "tags": list(self.tags),
            "attack_techniques": self.attack_techniques,
            "falsepositives": list(self.falsepositives),
            "references": list(self.references),
            "logsource": dict(self.logsource),
            "correlation": dict(self.correlation) if self.correlation else None,
            "source_file": self.source_file,
            "content_sha256": self.content_sha256,
            "test_count": len(self.tests),
        }

    def logsource_accepts(self, event: dict[str, Any]) -> bool:
        if not self.logsource:
            return True
        for key, path in (("service", "service.name"), ("protocol", "network.protocol"), ("transport", "network.transport")):
            allowed = self.logsource.get(key)
            if allowed is None:
                continue
            allowed_values = {str(item).lower() for item in (allowed if isinstance(allowed, list) else [allowed])}
            if str(get_field(event, path) or "").lower() not in allowed_values:
                return False
        return True


_REQUIRED = ("name", "id", "title", "level", "status")


def _rule_from_document(document: dict[str, Any], source_file: str) -> Rule:
    name = str(document.get("name") or document.get("id") or "<unnamed>")
    missing = [key for key in _REQUIRED if not document.get(key)]
    if missing:
        raise RuleError(f"{name}: missing required field(s) {missing}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9\-]{1,80}", name):
        raise RuleError(f"{name}: name must be lower-case kebab-case")
    level, status = str(document["level"]), str(document["status"])
    if level not in LEVELS:
        raise RuleError(f"{name}: level must be one of {LEVELS}")
    if status not in STATUSES:
        raise RuleError(f"{name}: status must be one of {STATUSES}")
    has_detection, has_correlation = "detection" in document, "correlation" in document
    if has_detection == has_correlation:
        raise RuleError(f"{name}: exactly one of 'detection' or 'correlation' is required")
    generate = bool(document.get("generate", True))
    detection_type = document.get("detection_type")
    if generate and not detection_type:
        raise RuleError(f"{name}: generating rules must declare detection_type")
    if detection_type and not re.fullmatch(r"[A-Z][A-Z0-9_]{2,60}", str(detection_type)):
        raise RuleError(f"{name}: detection_type must be UPPER_SNAKE_CASE")
    confidence = _number(document.get("confidence", 0.7))
    if confidence is None or not 0.0 < confidence <= 1.0:
        raise RuleError(f"{name}: confidence must be in (0, 1]")
    tags = tuple(str(tag).lower() for tag in document.get("tags") or [])
    canonical = yaml.safe_dump({k: v for k, v in document.items() if k != "tests"}, sort_keys=True)
    rule = Rule(
        name=name,
        id=str(document["id"]),
        title=str(document["title"]),
        version=int(document.get("version", 1)),
        status=status,
        level=level,
        description=str(document.get("description", "")).strip(),
        detection_type=str(detection_type) if detection_type else None,
        confidence=float(confidence),
        tags=tags,
        generate=generate,
        falsepositives=tuple(str(item) for item in document.get("falsepositives") or []),
        references=tuple(str(item) for item in document.get("references") or []),
        source_file=source_file,
        content_sha256=sha256(canonical.encode()).hexdigest(),
        logsource=dict(document.get("logsource") or {}),
        tests=list(document.get("tests") or []),
    )
    if has_detection:
        detection = document["detection"]
        if not isinstance(detection, dict) or "condition" not in detection:
            raise RuleError(f"{name}: detection needs selections and a condition")
        selections = {key: _compile_selection(name, key, body) for key, body in detection.items() if key != "condition"}
        if not selections:
            raise RuleError(f"{name}: detection has no selections")
        rule.matcher = _ConditionParser(name, _tokenize(name, str(detection["condition"])), selections).parse()
    else:
        correlation = dict(document["correlation"] or {})
        kind = correlation.get("type")
        if kind not in CORRELATION_TYPES:
            raise RuleError(f"{name}: correlation type must be one of {CORRELATION_TYPES}")
        references = correlation.get("rules")
        if isinstance(references, str):
            references = [references]
        if not references:
            raise RuleError(f"{name}: correlation must reference at least one rule")
        correlation["rules"] = [str(item) for item in references]
        correlation["timespan_seconds"] = parse_timespan(name, correlation.get("timespan"))
        correlation["group_by"] = [str(item) for item in correlation.get("group_by") or []]
        if kind in {"event_count", "value_count"}:
            correlation["comparison"] = _parse_comparison(name, correlation.get("condition"))
        if kind == "value_count" and not correlation.get("field"):
            raise RuleError(f"{name}: value_count correlation requires 'field'")
        if kind in {"temporal", "temporal_ordered"} and len(correlation["rules"]) < 2:
            raise RuleError(f"{name}: {kind} correlation needs at least two rules")
        rule.correlation = correlation
    return rule


# --------------------------------------------------------------------------- #
# Correlation evaluation
# --------------------------------------------------------------------------- #


def _time(event: dict[str, Any]) -> float:
    value = event.get("@timestamp") or event.get("timestamp")
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _event_id(event: dict[str, Any]) -> str | None:
    identifier = get_field(event, "event.id")
    return str(identifier) if identifier is not None else None


def _count_window(
    events: list[dict[str, Any]], timespan: float | None, operator: str, threshold: float, value_field: str | None
) -> tuple[bool, list[dict[str, Any]], float]:
    """Return (fired, evidence, observed) for a count/distinct-count condition.

    For ``gt``/``gte`` with a timespan, a two-pointer sliding window finds the
    densest qualifying window. Upper-bound conditions (``lt``/``lte``/``eq``)
    are evaluated over the whole group: "fewer than N within some window" is
    trivially true and would be meaningless.
    """
    if not events:
        return False, [], 0.0

    def measure(window: list[dict[str, Any]]) -> float:
        if value_field is None:
            return float(len(window))
        values = set()
        for event in window:
            value = get_field(event, value_field)
            for item in value if isinstance(value, list) else [value]:
                if item not in (None, ""):
                    values.add(str(item).lower())
        return float(len(values))

    if timespan is None or operator not in {"gt", "gte"}:
        observed = measure(events)
        return _compare(operator, observed, threshold), (events if _compare(operator, observed, threshold) else []), observed

    ordered = sorted(events, key=_time)
    best_observed, best_window = 0.0, []
    counts: dict[str, int] = {}
    left = 0
    for right, event in enumerate(ordered):
        if value_field is not None:
            value = get_field(event, value_field)
            for item in value if isinstance(value, list) else [value]:
                if item not in (None, ""):
                    counts[str(item).lower()] = counts.get(str(item).lower(), 0) + 1
        while _time(ordered[right]) - _time(ordered[left]) > timespan:
            if value_field is not None:
                value = get_field(ordered[left], value_field)
                for item in value if isinstance(value, list) else [value]:
                    if item not in (None, ""):
                        key = str(item).lower()
                        counts[key] -= 1
                        if counts[key] == 0:
                            del counts[key]
            left += 1
        observed = float(len(counts)) if value_field is not None else float(right - left + 1)
        if observed > best_observed:
            best_observed, best_window = observed, ordered[left : right + 1]
    fired = _compare(operator, best_observed, threshold)
    return fired, (best_window if fired else []), best_observed


def _temporal(matches: list[list[dict[str, Any]]], timespan: float | None, ordered: bool) -> tuple[bool, list[dict[str, Any]]]:
    if any(not group for group in matches):
        return False, []
    sorted_groups = [sorted(group, key=_time) for group in matches]
    limit = float("inf") if timespan is None else timespan
    if ordered:
        for anchor in sorted_groups[0]:
            chain, cursor = [anchor], _time(anchor)
            for group in sorted_groups[1:]:
                follower = next((event for event in group if _time(event) >= cursor), None)
                if follower is None:
                    break
                chain.append(follower)
                cursor = _time(follower)
            else:
                if _time(chain[-1]) - _time(chain[0]) <= limit:
                    return True, chain
        return False, []
    for anchor in sorted_groups[0]:
        start = _time(anchor)
        chain = [anchor]
        for group in sorted_groups[1:]:
            near = min(group, key=lambda event: abs(_time(event) - start))
            chain.append(near)
        times = [_time(event) for event in chain]
        if max(times) - min(times) <= limit:
            return True, chain
    return False, []


# --------------------------------------------------------------------------- #
# Rule set
# --------------------------------------------------------------------------- #


@dataclass
class RuleMatch:
    rule: Rule
    events: list[dict[str, Any]]
    observed: float | None = None

    @property
    def evidence_event_ids(self) -> list[str]:
        seen: list[str] = []
        for event in self.events:
            identifier = _event_id(event)
            if identifier and identifier not in seen:
                seen.append(identifier)
        return seen

    def reason(self) -> str:
        count = len(self.evidence_event_ids)
        if self.rule.correlation:
            kind = self.rule.correlation["type"]
            if kind in {"event_count", "value_count"}:
                operator, threshold = self.rule.correlation["comparison"]
                measure = "distinct " + self.rule.correlation["field"] if kind == "value_count" else "matching events"
                span = self.rule.correlation.get("timespan_seconds")
                window = f" within {span:g}s" if span else ""
                return f"{self.rule.title}: observed {self.observed:g} {measure}{window} ({operator} {threshold:g})."
            order = " in order" if kind == "temporal_ordered" else ""
            return f"{self.rule.title}: {' → '.join(self.rule.correlation['rules'])} observed{order}."
        return f"{self.rule.title}: {count} matching event(s)."


class RuleSet:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules: dict[str, Rule] = {}
        for rule in rules:
            if rule.name in self.rules:
                raise RuleError(f"duplicate rule name {rule.name!r}")
            if any(existing.id == rule.id for existing in self.rules.values()):
                raise RuleError(f"duplicate rule id {rule.id!r}")
            self.rules[rule.name] = rule
        for rule in self.rules.values():
            for reference in (rule.correlation or {}).get("rules", []):
                if reference not in self.rules:
                    raise RuleError(f"{rule.name}: correlation references unknown rule {reference!r}")
                if self.rules[reference].correlation:
                    raise RuleError(f"{rule.name}: correlations may only reference event rules")

    @property
    def version(self) -> str:
        digest = sha256("|".join(f"{name}:{rule.content_sha256}" for name, rule in sorted(self.rules.items())).encode()).hexdigest()
        return f"rules-{digest[:12]}"

    @property
    def detection_types(self) -> frozenset[str]:
        return frozenset(rule.detection_type for rule in self.rules.values() if rule.detection_type and rule.generate)

    def default_enabled(self, rule: Rule) -> bool:
        return rule.status != "deprecated"

    def evaluate(self, events: list[dict[str, Any]], *, enabled: dict[str, bool] | None = None) -> list[RuleMatch]:
        """Evaluate every enabled rule over one session's events."""
        overrides = enabled or {}
        is_on = {name: overrides.get(rule.id, overrides.get(name, self.default_enabled(rule))) for name, rule in self.rules.items()}
        enriched = [enrich(event) for event in events]
        event_matches: dict[str, list[dict[str, Any]]] = {}
        for name, rule in self.rules.items():
            if rule.matcher is None:
                continue
            matcher = rule.matcher
            event_matches[name] = [event for event in enriched if rule.logsource_accepts(event) and matcher(event)]
        results: list[RuleMatch] = []
        for name, rule in self.rules.items():
            if not is_on[name] or not rule.generate:
                continue
            if rule.matcher is not None:
                if event_matches[name]:
                    results.append(RuleMatch(rule, event_matches[name], float(len(event_matches[name]))))
                continue
            correlation = rule.correlation or {}
            referenced = [event_matches.get(reference, []) for reference in correlation["rules"]]
            kind = correlation["type"]
            if kind in {"event_count", "value_count"}:
                pool: dict[str, dict[str, Any]] = {}
                for group in referenced:
                    for event in group:
                        pool[_event_id(event) or str(id(event))] = event
                grouped: dict[tuple[str, ...], list[dict[str, Any]]] = {}
                for event in pool.values():
                    key = tuple(str(get_field(event, path)) for path in correlation["group_by"])
                    grouped.setdefault(key, []).append(event)
                operator, threshold = correlation["comparison"]
                best: RuleMatch | None = None
                for members in grouped.values():
                    fired, evidence, observed = _count_window(
                        members, correlation["timespan_seconds"], operator, threshold, correlation.get("field") if kind == "value_count" else None
                    )
                    if fired and (best is None or (best.observed or 0) < observed):
                        best = RuleMatch(rule, evidence, observed)
                if best is not None:
                    results.append(best)
            else:
                fired, evidence = _temporal(referenced, correlation["timespan_seconds"], kind == "temporal_ordered")
                if fired:
                    results.append(RuleMatch(rule, evidence, None))
        return results


def _expand_test_events(test: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(test.get("events") or []):
        item = dict(item)
        repeat = int(item.pop("repeat", 1))
        step = float(item.pop("every_seconds", 1))
        for copy in range(repeat):
            event = yaml.safe_load(yaml.safe_dump(item))
            event.setdefault("event", {}).setdefault("id", f"test-{index}-{copy}")
            if "@timestamp" not in event:
                event["@timestamp"] = datetime.fromtimestamp(_TEST_EPOCH + len(events) * step, tz=timezone.utc).isoformat()
            events.append(event)
    return events


def run_rule_tests(ruleset: RuleSet, rule_name: str | None = None) -> list[dict[str, Any]]:
    """Execute embedded ``tests:`` cases. Each case asserts whether the rule fires."""
    outcomes = []
    for name, rule in ruleset.rules.items():
        if rule_name and name != rule_name:
            continue
        for number, test in enumerate(rule.tests, start=1):
            events = _expand_test_events(test)
            fired = any(match.rule.name == name for match in ruleset.evaluate(events, enabled={name: True}))
            # Base rules with generate:false are tested through their own matcher.
            if not rule.generate and rule.matcher is not None:
                fired = any(rule.matcher(enrich(event)) and rule.logsource_accepts(enrich(event)) for event in events)
            expected = bool(test.get("match", True))
            outcomes.append({"rule": name, "test": test.get("name") or f"case-{number}", "expected": expected, "fired": fired, "passed": fired is expected})
    return outcomes


def load_rules(directory: Path | str | None = None) -> RuleSet:
    """Load and validate every ``*.yml`` rule under ``directory`` (recursively)."""
    root = Path(directory) if directory else RULES_DIR
    rules: list[Rule] = []
    for path in sorted(root.rglob("*.yml")):
        with path.open(encoding="utf-8") as stream:
            for document in yaml.safe_load_all(stream):
                if document is None:
                    continue
                if not isinstance(document, dict):
                    raise RuleError(f"{path.name}: every YAML document must be a mapping")
                rules.append(_rule_from_document(document, str(path.relative_to(root)).replace("\\", "/")))
    return RuleSet(rules)


_cached: RuleSet | None = None


def default_ruleset() -> RuleSet:
    global _cached
    if _cached is None:
        _cached = load_rules()
    return _cached
