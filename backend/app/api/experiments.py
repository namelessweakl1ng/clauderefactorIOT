import asyncio
from datetime import datetime, timezone
from time import monotonic
from uuid import uuid4

from fastapi import APIRouter, HTTPException

from ..config import get_settings
from ..elastic import store
from ..schemas import ExperimentCreate, GroundTruthSubmission
from ..services.detection.anomaly import load_latest_anomaly_model
from ..services.detection.rules import default_ruleset
from ..services.detector import DETECTOR_VERSION, detection_mode, get_active_policy, get_rule_states
from ..services.experiment_lab import compare_arms, dataset_bundle
from ..services.experiments import correlate, event_query, exact_filter, parse_time, validate_lab_host
from ..services.hardening import config as hardening_config
from ..services.ml.features import FEATURE_SCHEMA_VERSION
from ..services.scenarios import ScenarioCatalog, ScenarioCatalogError
from ..services.telemetry import SCHEMA_VERSION
from .common import one

router = APIRouter(prefix="/experiments", tags=["experiments"])
INDEX = "trapsig-experiments"


def _age_seconds(doc: dict) -> float | None:
    """Seconds since the experiment last made progress (end, start or creation time)."""
    stamp = parse_time(doc.get("end_time") or doc.get("start_time") or doc.get("created_at"))
    return (datetime.now(timezone.utc) - stamp).total_seconds() if stamp else None


async def abandon_stale(active: list[dict], keep: str) -> list[dict]:
    """Close orphaned running/correlating experiments; return the ones still blocking."""
    limit = get_settings().experiment_stale_seconds
    blocking = []
    for item in active:
        if item.get("experiment_id") == keep:
            continue
        age = _age_seconds(item)
        if age is not None and age > limit:
            item = {k: v for k, v in item.items() if k != "_id"}
            item.update(
                status="cancelled",
                result="INCONCLUSIVE",
                result_reason="STALE_ABANDONED",
                abandoned_at=now(),
                abandoned_reason=f"still {item.get('status')} after {int(age)} s (limit {limit} s); the run that owned it is gone",
            )
            await store.save(INDEX, item["experiment_id"], item)
        else:
            blocking.append(item)
    return blocking


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("")
async def experiments(include_archived: bool = False):
    try:
        records = await store.search(INDEX, size=200, sort_field="created_at", missing_index_is_empty=True)
    except TypeError as exc:
        # Compatibility with simple injected stores that predate the optional flag.
        if "missing_index_is_empty" not in str(exc):
            raise
        records = await store.search(INDEX, size=200, sort_field="created_at")
    return records if include_archived else [r for r in records if not r.get("archived")]


async def _deployment_snapshot() -> list[dict]:
    """Which personas (and content hashes) were live when the run started."""
    try:
        instances = await store.search("trapsig-sensor-instances", size=200, sort_field="received_at", missing_index_is_empty=True)
    except Exception:
        return []
    snapshot = []
    for doc in instances:
        persona = doc.get("persona") or {}
        services = sorted(f"{s.get('protocol')}/{s.get('public_port')}" for s in doc.get("services") or [] if s.get("listening"))
        snapshot.append(
            {
                "sensor_id": doc.get("sensor_id"),
                "persona_id": doc.get("persona_id"),
                "persona_version": persona.get("version"),
                "persona_sha256": persona.get("content_sha256"),
                "services": services,
                "received_at": doc.get("received_at"),
            }
        )
    return snapshot


@router.post("", status_code=201)
async def create(payload: ExperimentCreate):
    settings = get_settings()
    try:
        scenario = ScenarioCatalog().get(payload.scenario_id)
        attacker = validate_lab_host(payload.attacker_ip, settings.lab_subnet, "attacker_ip")
        target = validate_lab_host(payload.target_ip, settings.lab_subnet, "target_ip")
    except (ScenarioCatalogError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    identifier = "EXP-" + uuid4().hex[:12].upper()
    doc = {
        **payload.model_dump(),
        "attacker_ip": attacker,
        "target_ip": target,
        "target_honeypots": list(scenario.target_honeypots),
        "trial_kind": scenario.trial_kind,
        "expected_detection": scenario.expected_detection,
        "scenario_manifest_sha256": scenario.manifest_sha256,
        "scenario_step_services": list(scenario.step_services),
        "scenario_step_allowed_statuses": ["|".join(statuses) for statuses in scenario.step_allowed_statuses],
        "trapsig": {"schema_version": SCHEMA_VERSION},
        "experiment_id": identifier,
        "status": "created",
        "created_at": now(),
        "ground_truth_valid": False,
        "evaluation_step_time_tolerance_seconds": settings.evaluation_step_time_tolerance_seconds,
    }
    return await store.save(INDEX, identifier, doc)


@router.get("/{identifier}")
async def experiment(identifier: str):
    return await one(INDEX, identifier)


@router.post("/{identifier}/start")
async def start(identifier: str):
    doc = await experiment(identifier)
    if doc["status"] == "running":
        return doc
    if doc["status"] != "created":
        raise HTTPException(409, "only a created experiment can be started")
    try:
        scenario = ScenarioCatalog().get(doc["scenario_id"])
    except ScenarioCatalogError as exc:
        raise HTTPException(409, f"scenario is unavailable; create a new experiment: {exc}") from exc
    if scenario.manifest_sha256 != doc["scenario_manifest_sha256"]:
        raise HTTPException(409, "scenario manifest changed; create a new experiment")
    active = await store.search_all(INDEX, exact_filter("status", ["running", "correlating"]), sort=[{"created_at": "asc"}], missing_index_is_empty=True)
    blocking = await abandon_stale(active, identifier)
    if blocking:
        other = blocking[0]
        age = _age_seconds(other)
        raise HTTPException(
            409,
            f"another experiment is {other.get('status')}: {other.get('experiment_id')} ({other.get('scenario_id')}, "
            f"{int(age) if age is not None else '?'} s); finish or cancel it, or wait until it is older than "
            f"EXPERIMENT_STALE_SECONDS and it is abandoned automatically",
        )
    settings = get_settings()
    doc.update(
        status="running",
        start_time=now(),
        detector_ruleset_version=DETECTOR_VERSION,
        software_revision=settings.trapsig_revision,
        config_snapshot={
            "session_timeout_seconds": settings.session_timeout_seconds,
            "detector_ruleset_version": DETECTOR_VERSION,
            "policy_version": get_active_policy().policy_version,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "trapsig_schema_version": SCHEMA_VERSION,
            "software_revision": settings.trapsig_revision,
            "detection_mode": detection_mode(),
            "ruleset_version": default_ruleset().version,
            "rule_overrides": dict(sorted(get_rule_states().items())),
            "anomaly_model_version": getattr(await load_latest_anomaly_model(store), "model_version", None),
            "hardening": {
                **hardening_config(),
                "elevated_threshold_scale": settings.posture_elevated_threshold_scale,
                "locked_threshold_scale": settings.posture_locked_threshold_scale,
            },
            "deployments": await _deployment_snapshot(),
        },
    )
    doc.pop("_id", None)
    return await store.save(INDEX, identifier, doc)


@router.post("/{identifier}/cancel")
async def cancel(identifier: str):
    doc = await experiment(identifier)
    if doc["status"] == "cancelled":
        return doc
    if doc["status"] not in {"created", "running", "correlating"}:
        raise HTTPException(409, "only a created, running, or correlating experiment can be cancelled")
    doc.update(status="cancelled", cancelled_at=now())
    doc.pop("_id", None)
    return await store.save(INDEX, identifier, doc)


@router.post("/{identifier}/ground-truth")
async def ground_truth(identifier: str, payload: GroundTruthSubmission):
    doc = await experiment(identifier)
    if doc["status"] not in {"running", "correlating"}:
        raise HTTPException(409, "ground truth is accepted only while running or correlating")
    data = payload.model_dump(mode="json")
    if payload.experiment_id and payload.experiment_id != identifier:
        raise HTTPException(409, "ground-truth experiment_id mismatch")
    if payload.scenario_id != doc["scenario_id"] or payload.scenario_manifest_sha256 != doc["scenario_manifest_sha256"]:
        raise HTTPException(409, "ground-truth scenario or manifest mismatch")
    if payload.target != doc["target_ip"] or payload.expected_detection != doc["expected_detection"]:
        raise HTTPException(409, "ground-truth target or expected detection mismatch")
    if payload.end_time < payload.start_time or payload.start_time < parse_time(doc["start_time"]):
        raise HTTPException(422, "ground-truth times are outside the experiment window")
    if doc.get("end_time") and payload.end_time > parse_time(doc["end_time"]):
        raise HTTPException(422, "ground-truth ends after the experiment")
    existing = doc.get("ground_truth")
    if existing:
        if existing == data:
            return doc
        raise HTTPException(409, "a conflicting ground-truth run already exists")
    expected_steps = list(enumerate(doc.get("scenario_step_services", ()), start=1))
    actual_steps = [(step.step, step.service) for step in payload.steps]
    if not expected_steps or actual_steps != expected_steps:
        raise HTTPException(422, "ground-truth steps do not match the scenario manifest")
    allowed_statuses = doc.get("scenario_step_allowed_statuses", ())
    statuses_match_contract = len(allowed_statuses) == len(payload.steps) and all(
        step.status in contract.split("|") for step, contract in zip(payload.steps, allowed_statuses, strict=True)
    )
    valid = payload.overall_status == "completed" and statuses_match_contract
    doc.update(
        ground_truth=data,
        run_id=payload.run_id,
        runner_status=payload.overall_status,
        runner_start_time=data["start_time"],
        runner_end_time=data["end_time"],
        runner_steps=data["steps"],
        ground_truth_valid=valid,
    )
    doc.pop("_id", None)
    return await store.save(INDEX, identifier, doc)


async def settle(doc: dict) -> tuple[bool, float]:
    settings = get_settings()
    started, unchanged_since, previous = monotonic(), monotonic(), None
    while True:
        count = await store.count("trapsig-events-*", event_query(doc), missing_index_is_empty=True)
        if count != previous:
            previous, unchanged_since = count, monotonic()
        elapsed = monotonic() - started
        # Do not declare an empty stream settled after only the quiet period:
        # Filebeat may not have delivered its first matching event yet.
        if count > 0 and monotonic() - unchanged_since >= settings.experiment_settle_quiet_seconds:
            return True, elapsed
        if elapsed >= settings.experiment_settle_timeout_seconds:
            # Both an empty window and a still-changing stream are incomplete.
            # Neither may be silently interpreted as a negative observation.
            return False, elapsed
        await asyncio.sleep(settings.experiment_settle_poll_seconds)


@router.post("/{identifier}/finish")
async def finish(identifier: str):
    doc = await experiment(identifier)
    if doc["status"] == "completed":
        return doc
    if doc["status"] not in {"running", "correlating"}:
        raise HTTPException(409, "only a running or correlating experiment can be finished")
    if doc["status"] == "running":
        # Persist the evidence window before any settling I/O. A retry from
        # correlating deliberately reuses this immutable end time.
        doc.update(status="correlating", end_time=now())
        doc.pop("_id", None)
        await store.save(INDEX, identifier, doc)
    elif not doc.get("end_time"):
        raise HTTPException(409, "correlating experiment has no recorded end_time")
    doc.pop("_id", None)
    settled, wait = await settle(doc)
    doc.update(telemetry_settled=settled, settle_wait_seconds=wait)
    if not settled:
        doc = correlate(doc, [], [], [], scientific=True)
        doc.update(status="completed", result="INCONCLUSIVE", result_reason="SETTLE_TIMEOUT", observed_detection=None)
        return await store.save(INDEX, identifier, doc)
    try:
        from ..services import processor as processor_module

        if processor_module.processor:
            await processor_module.processor.process_once()
        events = await store.search_all("trapsig-events-*", event_query(doc), sort=[{"@timestamp": "asc"}], missing_index_is_empty=True)
        sessions = await store.search_all(
            "trapsig-sessions",
            {
                "bool": {
                    "filter": [
                        exact_filter("source_ip", doc["attacker_ip"]),
                        {"range": {"start_time": {"lte": doc["end_time"]}}},
                        {"range": {"end_time": {"gte": doc["start_time"]}}},
                    ]
                }
            },
            sort=[{"start_time": "asc"}],
            missing_index_is_empty=True,
        )
        session_ids = [s["session_id"] for s in sessions]
        detections = (
            []
            if not session_ids
            else await store.search_all("trapsig-detections", exact_filter("session_id", session_ids), sort=[{"timestamp": "asc"}], missing_index_is_empty=True)
        )
        doc = correlate(doc, events, sessions, detections, scientific=True)
    except Exception:
        doc = correlate(doc, [], [], [], scientific=True)
        doc.update(result="INCONCLUSIVE", result_reason="PROCESSING_ERROR", observed_detection=None)
    doc["status"] = "completed"
    return await store.save(INDEX, identifier, doc)


_DESIGN_FIELDS = (
    "name",
    "description",
    "scenario_id",
    "attacker_ip",
    "target_ip",
    "evaluation_batch_id",
    "objective",
    "hypothesis",
    "condition",
    "tags",
    "configuration",
)


@router.post("/{identifier}/duplicate", status_code=201)
async def duplicate(identifier: str):
    """Create a fresh experiment with the same design (scenario re-validated, new ID)."""
    source = await experiment(identifier)
    design = {field: source.get(field) for field in _DESIGN_FIELDS if source.get(field) is not None}
    design["name"] = (design.get("name") or identifier)[:113] + " (copy)"
    design["replicate"] = int(source.get("replicate") or 1) + 1
    try:
        payload = ExperimentCreate(**design)
    except ValueError as exc:
        raise HTTPException(422, f"source experiment design is no longer valid: {exc}") from exc
    created = await create(payload)
    created["duplicated_from"] = identifier
    return await store.save(INDEX, created["experiment_id"], {k: v for k, v in created.items() if k != "_id"})


async def _set_archived(identifier: str, archived: bool):
    doc = await experiment(identifier)
    if archived and doc["status"] in {"running", "correlating"}:
        raise HTTPException(409, "finish or cancel the experiment before archiving it")
    doc.update(archived=archived, archived_at=now() if archived else None)
    doc.pop("_id", None)
    return await store.save(INDEX, identifier, doc)


@router.post("/{identifier}/archive")
async def archive(identifier: str):
    return await _set_archived(identifier, True)


@router.post("/{identifier}/unarchive")
async def unarchive(identifier: str):
    return await _set_archived(identifier, False)


@router.get("/{identifier}/dataset")
async def dataset(identifier: str):
    """Hash-verified research bundle: experiment, ground truth, raw events, sessions, detections."""
    doc = await experiment(identifier)
    if doc.get("status") != "completed":
        raise HTTPException(409, "datasets are exported for completed experiments only")
    events = []
    ids = doc.get("event_ids") or []
    for offset in range(0, len(ids), 250):
        batch = ids[offset : offset + 250]
        events += await store.search_all("trapsig-events-*", exact_filter("event.id", batch), sort=[{"@timestamp": "asc"}], missing_index_is_empty=True)
    sessions = await store.search_all(
        "trapsig-sessions", exact_filter("session_id", doc.get("session_ids") or ["-"]), sort=[{"start_time": "asc"}], missing_index_is_empty=True
    )
    detections = await store.search_all(
        "trapsig-detections", exact_filter("detection_id", doc.get("detection_ids") or ["-"]), sort=[{"timestamp": "asc"}], missing_index_is_empty=True
    )
    return dataset_bundle(doc, events, sessions, detections)


lab = APIRouter(prefix="/experiment-lab", tags=["experiments"])


def _arm(records: list[dict], condition: str | None, batch: str | None) -> list[dict]:
    return [
        r
        for r in records
        if r.get("status") == "completed"
        and not r.get("archived")
        and (condition is None or r.get("condition") == condition)
        and (batch is None or r.get("evaluation_batch_id") == batch)
    ]


@lab.get("/conditions")
async def conditions():
    records = await store.search_all(INDEX, {"match_all": {}}, sort=[{"created_at": "asc"}], missing_index_is_empty=True)
    out: dict[str, dict] = {}
    for record in records:
        if record.get("archived"):
            continue
        key = record.get("condition") or "(none)"
        entry = out.setdefault(key, {"condition": key, "experiments": 0, "completed": 0, "batches": set()})
        entry["experiments"] += 1
        entry["completed"] += record.get("status") == "completed"
        if record.get("evaluation_batch_id"):
            entry["batches"].add(record["evaluation_batch_id"])
    return [{**v, "batches": sorted(v["batches"])} for v in sorted(out.values(), key=lambda v: v["condition"])]


@lab.get("/compare")
async def compare(condition_a: str, condition_b: str, batch_a: str | None = None, batch_b: str | None = None, alpha: float = 0.05):
    """Compare two arms (e.g. baseline vs adaptive-deception) on conclusive results."""
    if not 0 < alpha < 0.5:
        raise HTTPException(422, "alpha must be in (0, 0.5)")
    records = await store.search_all(INDEX, {"match_all": {}}, sort=[{"created_at": "asc"}], missing_index_is_empty=True)
    a, b = _arm(records, condition_a, batch_a), _arm(records, condition_b, batch_b)
    if not a or not b:
        raise HTTPException(404, "an arm has no completed, non-archived experiments")
    return compare_arms(a, b, labels=(condition_a, condition_b), alpha=alpha)
