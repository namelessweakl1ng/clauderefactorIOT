"""Event processor: events -> sessions -> detections -> RL hardening.

Incremental by default. Each cycle finds events *ingested* since a persisted
watermark (``event.ingested``, stamped by Logstash), takes only their source IPs,
and re-sessionizes those sources from the start of any session that is still open
for them. Work per cycle is proportional to new activity, not to index size, and
a session is never rewritten from a truncated window. A backlog drains in
``PROCESSING_BATCH_EVENTS`` chunks, oldest first. Every write uses a
deterministic ID, so the small re-read overlap (``PROCESSING_OVERLAP_SECONDS``)
and crash/restart are harmless. The watermark only advances after the cycle's
writes succeed.

Stores without point-in-time paging (unit-test doubles) fall back to the bounded
window of the newest ``PROCESSING_EVENT_LIMIT`` events.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import get_settings
from .detection.anomaly import load_latest_anomaly_model
from .detection.state import load_rule_states
from .detector import detect, get_rule_states, set_active_policy, set_anomaly_model, set_rule_states
from .hardening import HardeningAgent, threshold_scale_for
from .leader import LeaderElector
from .ml.store import load_latest_policy
from .sessionizer import reconstruct_sessions
from .telemetry import SCHEMA_VERSION, is_internal_event

LOGGER = logging.getLogger(__name__)
STATE_INDEX = "trapsig-processor-state"
WATERMARK_ID = "events-watermark"
SOURCE_CHUNK = 256


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _source_terms(field: str, values: list[str]) -> dict[str, Any]:
    return {"bool": {"should": [{"terms": {field: values}}, {"terms": {f"{field}.keyword": values}}], "minimum_should_match": 1}}


class EventProcessor:
    """Small idempotent materializer: deterministic IDs plus ES upserts survive restarts."""

    def __init__(self, store: Any) -> None:
        self.store = store
        self.hardening = HardeningAgent(store)
        self.leader = LeaderElector(store, ttl_seconds=get_settings().processor_lock_ttl_seconds)
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.last_run: str | None = None
        self.last_error: str | None = None
        self.sessions_written = 0
        self.detections_written = 0
        self.hardening_transitions = 0
        self.is_leader = True
        self.last_cycle: dict[str, Any] = {}

    async def _get(self, index: str, document_id: str) -> dict[str, Any] | None:
        if not hasattr(self.store, "get"):
            return None
        try:
            return await self.store.get(index, document_id)
        except Exception:
            return None

    async def load_events(self, now: datetime | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Events to (re)process this cycle, plus cycle metadata incl. the next watermark."""
        settings = get_settings()
        if not hasattr(self.store, "search_all"):
            window = await self.store.search("trapsig-events-*", size=settings.processing_event_limit, sort_field="@timestamp")
            return window, {"mode": "window", "events_loaded": len(window)}
        now = now or datetime.now(timezone.utc)
        state = await self._get(STATE_INDEX, WATERMARK_ID)
        since = _parse((state or {}).get("ingested_through")) or now - timedelta(seconds=settings.processing_backfill_seconds)
        upper = now - timedelta(seconds=settings.processing_ingest_lag_seconds)
        meta: dict[str, Any] = {
            "mode": "incremental",
            "since": _iso(since),
            "through": _iso(max(since, upper)),
            "new_events": 0,
            "sources": 0,
            "events_loaded": 0,
        }
        if upper <= since:
            return [], meta
        lower = since - timedelta(seconds=settings.processing_overlap_seconds)
        new = await self.store.search_all(
            "trapsig-events-*",
            {"range": {"event.ingested": {"gt": _iso(lower), "lte": _iso(upper)}}},
            sort=[{"event.ingested": "asc"}],
            missing_index_is_empty=True,
            limit=settings.processing_batch_events,
        )
        if len(new) >= settings.processing_batch_events:
            # Backlog: advance only to what was read, the rest follows next cycle.
            last = _parse((new[-1].get("event") or {}).get("ingested"))
            meta["through"] = _iso(last) if last and last > since else meta["through"]
            meta["backlog"] = True
        new = [e for e in new if not is_internal_event(e) and (e.get("source") or {}).get("ip") and e.get("@timestamp")]
        meta["new_events"] = len(new)
        if not new:
            return [], meta
        sources = sorted({e["source"]["ip"] for e in new})
        earliest = min(_parse(e["@timestamp"]) or now for e in new) - timedelta(seconds=settings.session_timeout_seconds)
        # A session still open at `earliest` must be rebuilt from its own start.
        open_sessions = await self.store.search_all(
            "trapsig-sessions",
            {"bool": {"filter": [_source_terms("source_ip", sources), {"range": {"end_time": {"gte": _iso(earliest)}}}]}},
            sort=[{"start_time": "asc"}],
            missing_index_is_empty=True,
        )
        start = min([earliest, *(t for t in (_parse(s.get("start_time")) for s in open_sessions) if t)])
        events: list[dict[str, Any]] = []
        for offset in range(0, len(sources), SOURCE_CHUNK):
            chunk = sources[offset : offset + SOURCE_CHUNK]
            events += await self.store.search_all(
                "trapsig-events-*",
                {"bool": {"filter": [_source_terms("source.ip", chunk), {"range": {"@timestamp": {"gte": _iso(start)}}}]}},
                sort=[{"@timestamp": "asc"}],
                missing_index_is_empty=True,
            )
        meta.update(sources=len(sources), events_loaded=len(events), window_start=_iso(start))
        return events, meta

    async def _save_watermark(self, meta: dict[str, Any]) -> None:
        if meta.get("mode") != "incremental":
            return
        document = {"ingested_through": meta["through"], "updated_at": _iso(datetime.now(timezone.utc)), "last_cycle": meta}
        await self.store.save(STATE_INDEX, WATERMARK_ID, document, refresh=False)

    async def process_once(self) -> dict[str, int]:
        settings = get_settings()
        # Pick up the most recent trained policy generation (one cheap size=1
        # search). Falls back to the deterministic bootstrap policy when no
        # generation exists yet or ES is unreachable -- detection never blocks on
        # training state.
        policy = await load_latest_policy(self.store)
        set_active_policy(policy)
        set_rule_states(await load_rule_states(self.store, get_rule_states()))
        set_anomaly_model(await load_latest_anomaly_model(self.store))
        # Previous-cycle posture decides this cycle's per-IP detection sensitivity.
        posture_levels = await self.hardening.current_levels()
        events, cycle = await self.load_events()
        sessions = reconstruct_sessions(
            [event for event in events if not is_internal_event(event)],
            settings.session_timeout_seconds,
        )
        detections: list[dict[str, Any]] = []
        for session in sessions:
            level = posture_levels.get(str(session.get("source_ip")), "normal")
            detections.extend(detect(session, policy=policy, threshold_scale=threshold_scale_for(level)))
            stored = {key: value for key, value in session.items() if key != "events"}
            stored["trapsig"] = {"schema_version": SCHEMA_VERSION}
            await self.store.save("trapsig-sessions", session["session_id"], stored, refresh=False)
        for detection in detections:
            existing = (await self.store.get("trapsig-detections", detection["detection_id"])) if hasattr(self.store, "get") else None
            if existing and existing.get("detected_at"):
                detection["detected_at"] = existing["detected_at"]
            detection["trapsig"] = {"schema_version": SCHEMA_VERSION}
            await self.store.save("trapsig-detections", detection["detection_id"], detection, refresh=False)
        if sessions or detections:
            await self.store.refresh("trapsig-sessions", "trapsig-detections")
        # The resulting posture takes effect on sensors within one poll interval
        # and as detection sensitivity on the next cycle (read above).
        # RL hardening: learn from finished decisions, decide for active sources.
        transitions = await self.hardening.step(detections)
        await self._save_watermark(cycle)
        self.last_cycle = {**cycle, "sessions": len(sessions), "detections": len(detections)}
        self.sessions_written = len(sessions)
        self.detections_written = len(detections)
        self.hardening_transitions = len(transitions)
        self.last_run = datetime.now(timezone.utc).isoformat()
        self.last_error = None
        return {"sessions": len(sessions), "detections": len(detections)}

    async def run(self) -> None:
        settings = get_settings()
        interval = settings.processing_interval_seconds
        while not self._stop.is_set():
            try:
                if not settings.processor_enabled:
                    self.is_leader = False
                elif settings.processor_leader_election and not await self.leader.is_leader():
                    # Another replica is the active writer this round; stand by.
                    self.is_leader = False
                else:
                    self.is_leader = True
                    await self.process_once()
            except Exception as exc:
                self.last_error = str(exc)
                LOGGER.exception("event processing cycle failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
        await self.leader.release()

    def status(self) -> dict[str, Any]:
        return {
            "last_run": self.last_run,
            "last_error": self.last_error,
            "sessions_written": self.sessions_written,
            "detections_written": self.detections_written,
            "hardening_transitions": self.hardening_transitions,
            "last_cycle": self.last_cycle,
            "is_leader": self.is_leader,
            "leader_owner": self.leader.owner if self.leader.enabled else None,
        }


processor: EventProcessor | None = None


def configure_processor(store: Any) -> EventProcessor:
    global processor
    processor = EventProcessor(store)
    return processor
