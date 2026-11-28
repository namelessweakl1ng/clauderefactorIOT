"""Detection laboratory API: rules, engines, ATT&CK coverage, engine comparisons."""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from ..config import get_settings
from ..elastic import store
from ..security import principal_of
from ..services.detection.anomaly import load_latest_anomaly_model
from ..services.detection.attack import TACTIC_ORDER, TECHNIQUES, TYPE_DEFAULTS
from ..services.detection.comparison import COMPARISON_INDEX, compare, labeled_from_experiments, synthetic_corpus
from ..services.detection.rules import RuleSet, default_ruleset, enrich, run_rule_tests
from ..services.detection.state import load_rule_states, save_rule_state
from ..services.detector import DETECTOR_VERSION, detection_mode, get_active_policy

router = APIRouter(prefix="/detection", tags=["detection"])


def _rule(identifier: str):
    ruleset = default_ruleset()
    for rule in ruleset.rules.values():
        if identifier in {rule.id, rule.name}:
            return rule
    raise HTTPException(404, "unknown rule")


async def _states() -> dict[str, bool]:
    return await load_rule_states(store)


@router.get("/engines")
async def engines() -> dict[str, Any]:
    ruleset = default_ruleset()
    policy = get_active_policy()
    anomaly = await load_latest_anomaly_model(store)
    return {
        "mode": detection_mode(),
        "detector_version": DETECTOR_VERSION,
        "rules": {"version": ruleset.version, "count": len(ruleset.rules), "generating": sum(r.generate for r in ruleset.rules.values())},
        "ml": {
            "policy_version": policy.policy_version,
            "heads": policy.detection_types,
            "feature_names": list(policy.feature_names),
            "confidence_calibrated": False,
        },
        "anomaly": (
            {"model_version": anomaly.model_version, "threshold": anomaly.threshold, "trained_on": anomaly.trained_on, "trees": len(anomaly.trees)}
            if anomaly
            else None
        ),
    }


@router.get("/rules")
async def rules() -> list[dict[str, Any]]:
    states = await _states()
    ruleset = default_ruleset()
    out = []
    for rule in ruleset.rules.values():
        enabled = states.get(rule.id, ruleset.default_enabled(rule))
        out.append({**rule.metadata(), "enabled": enabled, "override": rule.id in states})
    return sorted(out, key=lambda item: (item["kind"] != "correlation" and item["generate"] is False, item["name"]))


@router.get("/rules/self-test")
async def self_test() -> dict[str, Any]:
    outcomes = run_rule_tests(default_ruleset())
    return {
        "ruleset_version": default_ruleset().version,
        "cases": len(outcomes),
        "passed": sum(o["passed"] for o in outcomes),
        "failures": [o for o in outcomes if not o["passed"]],
    }


@router.get("/rules/{identifier}")
async def rule_detail(identifier: str) -> dict[str, Any]:
    rule = _rule(identifier)
    states = await _states()
    return {
        **rule.metadata(),
        "enabled": states.get(rule.id, default_ruleset().default_enabled(rule)),
        "tests": rule.tests,
        "test_results": run_rule_tests(default_ruleset(), rule.name),
    }


class RuleStateChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    reason: str | None = Field(default=None, max_length=500)


@router.post("/rules/{identifier}/state")
async def set_rule_state(identifier: str, payload: RuleStateChange, request: Request) -> dict[str, Any]:
    rule = _rule(identifier)
    document = await save_rule_state(store, rule.id, payload.enabled, actor=principal_of(request).name, reason=payload.reason)
    return {"rule": rule.name, **document}


class RuleTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


@router.post("/rules/{identifier}/test")
async def test_rule(identifier: str, payload: RuleTestRequest) -> dict[str, Any]:
    """Evaluate one rule (and the event rules it references) against supplied events."""
    target = _rule(identifier)
    ruleset = default_ruleset()
    needed = [target, *[ruleset.rules[name] for name in (target.correlation or {}).get("rules", [])]]
    scoped = RuleSet(needed)
    enabled = {rule.id: True for rule in needed}
    events = []
    for index, event in enumerate(payload.events):
        event = dict(event)
        event.setdefault("event", {}).setdefault("id", f"input-{index}")
        events.append(event)
    matches = [m for m in scoped.evaluate(events, enabled=enabled) if m.rule.name == target.name]
    per_event = []
    if target.matcher is not None:
        per_event = [{"event_id": e["event"]["id"], "matched": bool(target.logsource_accepts(enrich(e)) and target.matcher(enrich(e)))} for e in events]
    return {
        "rule": target.name,
        "fired": bool(matches),
        "reason": matches[0].reason() if matches else None,
        "observed": matches[0].observed if matches else None,
        "evidence_event_ids": matches[0].evidence_event_ids if matches else [],
        "per_event": per_event,
    }


@router.get("/attack")
async def attack_coverage() -> dict[str, Any]:
    """ATT&CK catalogue with which rules/types cover each technique and observed counts."""
    ruleset = default_ruleset()
    covering: dict[str, list[str]] = {}
    for rule in ruleset.rules.values():
        for technique in rule.attack_techniques:
            covering.setdefault(technique, []).append(rule.name)
    defaults: dict[str, list[str]] = {}
    for kind, techniques in TYPE_DEFAULTS.items():
        for technique in techniques:
            defaults.setdefault(technique, []).append(kind)
    observed: dict[str, int] = {}
    try:
        result = await store.aggregate(
            "trapsig-detections",
            {"match_all": {}},
            {"techniques": {"terms": {"field": "attack.id", "size": 200}}},
            missing_index_is_empty=True,
        )
        observed = {b["key"]: int(b["doc_count"]) for b in (result.get("aggregations", {}).get("techniques", {}) or {}).get("buckets", [])}
    except Exception:
        observed = {}
    techniques = [
        {
            "id": tid,
            **entry,
            "rules": sorted(covering.get(tid, [])),
            "default_for_types": sorted(defaults.get(tid, [])),
            "observed_detections": observed.get(tid, 0),
        }
        for tid, entry in TECHNIQUES.items()
    ]
    return {"tactics": list(TACTIC_ORDER), "techniques": techniques}


@router.get("/comparisons")
async def comparisons() -> list[dict[str, Any]]:
    documents = await store.search(COMPARISON_INDEX, size=50, sort_field="created_at", missing_index_is_empty=True)
    return documents


@router.get("/comparisons/{identifier}")
async def comparison(identifier: str) -> dict[str, Any]:
    document = await store.get(COMPARISON_INDEX, identifier)
    if document is None:
        raise HTTPException(404, "unknown comparison")
    return document


class ComparisonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["synthetic", "logged"] = "synthetic"
    folds: int = Field(default=5, ge=2, le=10)
    seed: int = Field(default=20261126, ge=0)
    epochs: int = Field(default=200, ge=20, le=1000)


async def logged_samples() -> list[Any]:
    from ..tools.train_detector import _completed_experiments, _sessions_for

    timeout = get_settings().session_timeout_seconds
    pairs = []
    for experiment in await _completed_experiments(store):
        sessions = await _sessions_for(store, experiment, timeout)
        if sessions:
            pairs.append((experiment, sessions))
    return labeled_from_experiments(pairs)


@router.post("/comparisons", status_code=201)
async def run_comparison(payload: ComparisonRequest, request: Request) -> dict[str, Any]:
    """Run a grouped-CV engine comparison and store the report (CPU-bound; runs in a worker thread)."""
    samples = synthetic_corpus(seed=payload.seed % 10_000) if payload.source == "synthetic" else await logged_samples()
    if len({s.group for s in samples}) < 2:
        raise HTTPException(409, "need labeled sessions from at least two experiments/groups; run conclusive experiments first or use source=synthetic")
    try:
        report = await asyncio.to_thread(compare, samples, folds=payload.folds, seed=payload.seed, epochs=payload.epochs)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    report["requested_by"] = principal_of(request).name
    report["parameters"] = payload.model_dump()
    await store.save(COMPARISON_INDEX, report["report_id"], report)
    return report


_MODEL_FIELDS = ("policy_version", "trained_at", "source", "training_example_count", "feature_schema_version", "experiments_used", "active")


@router.get("/model-history")
async def model_history() -> list[dict[str, Any]]:
    """Generations of the supervised ML detector (``tools/train_detector.py``)."""
    documents = await store.search("trapsig-policy", size=100, sort_field="trained_at", missing_index_is_empty=True)
    rows = []
    for document in documents:
        row = {field: document.get(field) for field in _MODEL_FIELDS}
        evaluation = document.get("evaluation") or {}
        row["validation_macro_f1"] = (evaluation.get("validation") or {}).get("macro_f1")
        row["validation_ece"] = (evaluation.get("validation") or {}).get("ece")
        row["baseline_macro_f1"] = (evaluation.get("rule_baseline") or {}).get("macro_f1")
        row["calibrated"] = bool(document.get("calibration"))
        rows.append(row)
    return rows
