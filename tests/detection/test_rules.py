"""Rule engine: grammar, modifiers, correlations, validation and the shipped pack."""

import pytest
import yaml

from backend.app.services.detection.attack import TECHNIQUES
from backend.app.services.detection.rules import RuleError, RuleSet, _rule_from_document, default_ruleset, load_rules, run_rule_tests


def rule(**overrides):
    document = {
        "name": "t-rule",
        "id": "00000000-0000-0000-0000-000000000001",
        "title": "Test rule",
        "status": "test",
        "level": "medium",
        "detection_type": "TEST_TYPE",
        "detection": {"selection": {"event.category": "authentication"}, "condition": "selection"},
    }
    document.update(overrides)
    return _rule_from_document(document, "inline.yml")


def fires(r, events, extra=()):
    return any(m.rule.name == r.name for m in RuleSet([r, *extra]).evaluate(events))


# ---- shipped pack ---------------------------------------------------------- #


def test_every_shipped_rule_passes_its_embedded_tests():
    outcomes = run_rule_tests(default_ruleset())
    failures = [o for o in outcomes if not o["passed"]]
    assert outcomes and not failures, failures


def test_every_generating_rule_has_positive_and_negative_tests():
    for name, r in default_ruleset().rules.items():
        if not r.generate:
            continue
        expectations = {bool(t.get("match", True)) for t in r.tests}
        assert expectations == {True, False}, f"{name} needs both a positive and a negative case"


def test_every_attack_tag_is_in_the_catalogue():
    for name, r in default_ruleset().rules.items():
        for technique in r.attack_techniques:
            assert technique in TECHNIQUES, f"{name} references unknown technique {technique}"


def test_ruleset_version_changes_with_content(tmp_path):
    base = load_rules()
    for path in (tmp_path / "a.yml",):
        path.write_text(yaml.safe_dump({**_doc(), "level": "high"}))
    one = load_rules(tmp_path)
    (tmp_path / "a.yml").write_text(yaml.safe_dump({**_doc(), "level": "low"}))
    two = load_rules(tmp_path)
    assert one.version != two.version != base.version


def _doc():
    return {
        "name": "a-rule",
        "id": "00000000-0000-0000-0000-00000000000a",
        "title": "A",
        "status": "test",
        "level": "high",
        "detection_type": "A_TYPE",
        "detection": {"s": {"x": 1}, "condition": "s"},
    }


# ---- grammar --------------------------------------------------------------- #


@pytest.mark.parametrize(
    "condition,event,expected",
    [
        ("a and b", {"x": 1, "y": 2}, True),
        ("a and b", {"x": 1}, False),
        ("a or b", {"y": 2}, True),
        ("a and not b", {"x": 1, "y": 2}, False),
        ("not (a or b)", {"z": 1}, True),
        ("1 of sel*", {"y": 2}, True),
        ("all of sel*", {"y": 2}, False),
        ("all of them", {"x": 1, "y": 2, "z": 3}, True),
        ("1 of them and not a", {"z": 3}, True),
    ],
)
def test_condition_grammar(condition, event, expected):
    r = rule(detection={"a": {"x": 1}, "b": {"y": 2}, "sel_one": {"x": 1}, "sel_two": {"y": 2}, "c": {"z": 3}, "condition": condition})
    assert fires(r, [{"event": {"id": "1"}, **event}]) is expected


@pytest.mark.parametrize(
    "bad",
    ["a and", "(a or b", "a xor b", "unknown", "1 of nomatch*"],
)
def test_malformed_conditions_are_rejected(bad):
    with pytest.raises(RuleError):
        rule(detection={"a": {"x": 1}, "b": {"y": 1}, "condition": bad})


# ---- modifiers ------------------------------------------------------------- #


@pytest.mark.parametrize(
    "field,value,actual,expected",
    [
        ("p", "ADMIN", "admin", True),  # case-insensitive by default
        ("p|cased", "ADMIN", "admin", False),
        ("p", "/cgi-*", "/cgi-bin/x", True),  # wildcard
        ("p|contains", "bin", "/cgi-bin/x", True),
        ("p|startswith", "/cgi", "/cgi-bin/x", True),
        ("p|endswith", ".env", "/app/.env", True),
        ("p|re", r"^\d{3}$", "123", True),
        ("p|re", r"^\d{3}$", "1234", False),
        ("ip|cidr", "192.168.50.0/24", "192.168.50.7", True),
        ("ip|cidr", "192.168.50.0/24", "10.0.0.1", False),
        ("n|gte", 5, 5, True),
        ("n|gt", 5, 5, False),
        ("n|lt", 5, "4", True),
        ("p|exists", True, "x", True),
        ("p|exists", False, None, True),
        ("p", ["a", "b"], "b", True),
        ("tags|all", ["a", "b"], ["a", "b", "c"], True),
        ("tags|all", ["a", "d"], ["a", "b", "c"], False),
        ("n", 6, "6", True),
        ("flag", True, True, True),
        ("flag", True, "true", False),
    ],
)
def test_value_modifiers(field, value, actual, expected):
    path = field.split("|")[0]
    r = rule(detection={"s": {field: value}, "condition": "s"})
    event = {"event": {"id": "1"}}
    if actual is not None:
        event[path] = actual
    assert fires(r, [event]) is expected


def test_list_of_maps_selection_is_an_or():
    r = rule(detection={"s": [{"x": 1}, {"y": 2}], "condition": "s"})
    assert fires(r, [{"y": 2}])
    assert not fires(r, [{"z": 3}])


def test_dotted_paths_resolve_nested_and_list_values():
    r = rule(detection={"s": {"a.b": "v"}, "condition": "s"})
    assert fires(r, [{"a": {"b": ["u", "v"]}}])


@pytest.mark.parametrize(
    "overrides",
    [
        {"level": "severe"},
        {"status": "beta"},
        {"name": "Bad Name"},
        {"confidence": 1.5},
        {"detection_type": "lower"},
        {"detection": {"s": {"x|nosuchmod": 1}, "condition": "s"}},
        {"detection": {"s": {"x|re": "("}, "condition": "s"}},
        {"detection": {"s": {"x|cidr": "nonsense"}, "condition": "s"}},
        {"detection": {"condition": "s"}},
    ],
)
def test_invalid_rules_are_rejected(overrides):
    with pytest.raises(RuleError):
        rule(**overrides)


def test_generating_rule_requires_type_and_one_logic_block():
    with pytest.raises(RuleError):
        rule(detection_type=None)
    with pytest.raises(RuleError):
        rule(correlation={"type": "event_count", "rules": ["x"], "condition": {"gte": 1}})


# ---- correlations ---------------------------------------------------------- #


def base(name="base", **detection):
    return _rule_from_document(
        {
            "name": name,
            "id": f"id-{name}",
            "title": name,
            "status": "test",
            "level": "informational",
            "generate": False,
            "detection": detection or {"s": {"k": "v"}, "condition": "s"},
        },
        "inline.yml",
    )


def correlation(**spec):
    return _rule_from_document(
        {"name": "corr", "id": "id-corr", "title": "Corr", "status": "test", "level": "high", "detection_type": "CORR", "correlation": spec},
        "inline.yml",
    )


def at(seconds, **fields):
    from datetime import datetime, timedelta, timezone

    stamp = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat()
    return {"@timestamp": stamp, "event": {"id": f"e{seconds}-{len(fields)}-{sorted(fields.items())}"}, **fields}


def test_event_count_sliding_window_and_exact_evidence():
    corr = correlation(type="event_count", rules=["base"], timespan="60s", condition={"gte": 3})
    rs = RuleSet([base(), corr])
    sparse = [at(0, k="v"), at(100, k="v"), at(200, k="v")]
    assert not [m for m in rs.evaluate(sparse) if m.rule.name == "corr"]
    dense = sparse + [at(210, k="v"), at(220, k="v"), at(230, k="other")]
    match = next(m for m in rs.evaluate(dense) if m.rule.name == "corr")
    assert match.observed == 3
    # evidence = exactly the qualifying window, never the non-matching event
    assert len(match.evidence_event_ids) == 3
    assert all("other" not in eid for eid in match.evidence_event_ids)


def test_value_count_with_group_by():
    corr = correlation(type="value_count", rules=["base"], field="u", group_by=["svc"], condition={"gte": 2})
    rs = RuleSet([base(), corr])
    split = [at(0, k="v", u="a", svc="x"), at(1, k="v", u="b", svc="y")]
    assert not [m for m in rs.evaluate(split) if m.rule.name == "corr"]
    same = [at(0, k="v", u="a", svc="x"), at(1, k="v", u="b", svc="x")]
    assert [m for m in rs.evaluate(same) if m.rule.name == "corr"]


def test_temporal_ordered_respects_order_and_span():
    first, second = base("first", s={"k": 1}, condition="s"), base("second", s={"k": 2}, condition="s")
    corr = correlation(type="temporal_ordered", rules=["first", "second"], timespan="30s")
    rs = RuleSet([first, second, corr])
    assert [m for m in rs.evaluate([at(0, k=1), at(10, k=2)]) if m.rule.name == "corr"]
    assert not [m for m in rs.evaluate([at(0, k=2), at(10, k=1)]) if m.rule.name == "corr"]
    assert not [m for m in rs.evaluate([at(0, k=1), at(100, k=2)]) if m.rule.name == "corr"]
    unordered = correlation(type="temporal", rules=["first", "second"], timespan="30s")
    assert [m for m in RuleSet([first, second, unordered]).evaluate([at(0, k=2), at(10, k=1)]) if m.rule.name == "corr"]


def test_correlation_reference_integrity():
    with pytest.raises(RuleError):
        RuleSet([correlation(type="event_count", rules=["missing"], condition={"gte": 1})])


def test_disabled_and_deprecated_rules_do_not_fire():
    r = rule()
    event = [{"event": {"id": "1", "category": "authentication"}}]
    assert RuleSet([r]).evaluate(event)
    assert not RuleSet([r]).evaluate(event, enabled={r.id: False})
    deprecated = rule(status="deprecated")
    assert not RuleSet([deprecated]).evaluate(event)
    assert RuleSet([deprecated]).evaluate(event, enabled={deprecated.id: True})


def test_logsource_prefilter():
    r = rule(logsource={"service": ["cowrie"]})
    assert fires(r, [{"event": {"category": "authentication"}, "service": {"name": "cowrie"}}])
    assert not fires(r, [{"event": {"category": "authentication"}, "service": {"name": "camera"}}])
