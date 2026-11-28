"""Incremental processing: watermark on event.ingested, only affected sources are
re-sessionized, open sessions are rebuilt whole, backlogs drain in batches."""

import asyncio
import dataclasses
from datetime import datetime, timedelta, timezone

from backend.app.services import processor as proc
from backend.app.services.processor import STATE_INDEX, WATERMARK_ID, EventProcessor

T0 = datetime(2026, 11, 27, 10, 0, tzinfo=timezone.utc)


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def dotted(doc, field):
    for part in field.removesuffix(".keyword").split("."):
        doc = (doc or {}).get(part) if isinstance(doc, dict) else None
    return doc


def matches(doc, query):
    if not query:
        return True
    if "range" in query:
        ((field, bounds),) = query["range"].items()
        value = dotted(doc, field)
        if value is None:
            return False
        ops = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b, "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b}
        return all(ops[op](value, bound) for op, bound in bounds.items())
    if "terms" in query:
        ((field, values),) = query["terms"].items()
        return dotted(doc, field) in values
    if "bool" in query:
        b = query["bool"]
        return all(matches(doc, q) for q in b.get("filter", [])) and (not b.get("should") or any(matches(doc, q) for q in b["should"]))
    raise AssertionError(f"unsupported query {query}")


class Store:
    def __init__(self):
        self.docs: dict[str, dict[str, dict]] = {}
        self.event_reads = 0

    def add_event(self, eid, ip, at, ingested, service="cowrie"):
        doc = {
            "@timestamp": iso(at),
            "event": {"id": eid, "category": "authentication", "outcome": "failure", "ingested": iso(ingested)},
            "source": {"ip": ip},
            "service": {"name": service},
            "honeypot": {"id": service},
            "network": {"protocol": "ssh"},
            "authentication": {"username": "admin", "password": "x"},
        }
        self.docs.setdefault("trapsig-events-2026.11.27", {})[eid] = doc

    def _index(self, pattern):
        if pattern.endswith("*"):
            return [d for name, docs in self.docs.items() if name.startswith(pattern[:-1]) for d in docs.values()]
        return list(self.docs.get(pattern, {}).values())

    async def search_all(self, index, query=None, *, sort=None, page_size=500, missing_index_is_empty=False, limit=None):
        found = [d for d in self._index(index) if matches(d, query)]
        if sort:
            ((field, order),) = sort[0].items()
            found.sort(key=lambda d: str(dotted(d, field)), reverse=order == "desc")
        if index.startswith("trapsig-events"):
            self.event_reads += len(found[:limit] if limit else found)
        return found[:limit] if limit else found

    async def search(self, index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
        return sorted([d for d in self._index(index) if matches(d, query)], key=lambda d: str(dotted(d, sort_field)), reverse=True)[:size]

    async def get(self, index, document_id):
        return self.docs.get(index, {}).get(document_id)

    async def save(self, index, document_id, document, *, refresh="wait_for"):
        self.docs.setdefault(index, {})[document_id] = dict(document)
        return document

    async def refresh(self, *indices):
        pass


def cycle(store, now, monkeypatch, **overrides):
    settings = dataclasses.replace(proc.get_settings(), **{"processing_ingest_lag_seconds": 0, "processing_overlap_seconds": 0, **overrides})
    monkeypatch.setattr(proc, "get_settings", lambda: settings)
    processor = EventProcessor(store)
    original = processor.load_events
    processor.load_events = lambda: original(now)  # pin the clock for determinism
    asyncio.run(processor.process_once())
    return processor.last_cycle


def sessions(store):
    return list(store.docs.get("trapsig-sessions", {}).values())


def test_only_new_activity_is_reprocessed_and_sessions_are_never_truncated(monkeypatch):
    store = Store()
    for i in range(5):
        store.add_event(f"a{i}", "192.168.50.20", T0 + timedelta(seconds=i), T0 + timedelta(seconds=i + 1))
    for i in range(40):  # a second, unrelated source
        store.add_event(f"b{i}", "192.168.50.30", T0 + timedelta(seconds=i), T0 + timedelta(seconds=i + 1))
    first = cycle(store, T0 + timedelta(minutes=1), monkeypatch)
    assert first["mode"] == "incremental" and first["sources"] == 2 and first["sessions"] == 2
    watermark = store.docs[STATE_INDEX][WATERMARK_ID]["ingested_through"]
    assert watermark == iso(T0 + timedelta(minutes=1))

    quiet = cycle(store, T0 + timedelta(minutes=2), monkeypatch)
    assert quiet["new_events"] == 0 and quiet["sessions"] == 0  # nothing new: nothing rewritten

    # A continues its session; only A is reloaded, and its session keeps all six events.
    store.add_event("a5", "192.168.50.20", T0 + timedelta(seconds=90), T0 + timedelta(minutes=2, seconds=30))
    store.event_reads = 0
    third = cycle(store, T0 + timedelta(minutes=3), monkeypatch)
    assert third["sources"] == 1 and third["sessions"] == 1
    assert store.event_reads == 1 + 6  # the new event, then A's six; none of B's forty
    a = next(s for s in sessions(store) if s["source_ip"] == "192.168.50.20")
    assert a["event_count"] == 6 and len(sessions(store)) == 2  # same session id, upserted whole


def test_long_open_session_is_rebuilt_from_its_own_start(monkeypatch):
    store = Store()
    # One event every 4 minutes for an hour: a single session (timeout 300 s) much longer than the timeout.
    for i in range(16):
        store.add_event(f"s{i}", "192.168.50.40", T0 + timedelta(minutes=4 * i), T0 + timedelta(minutes=4 * i, seconds=1))
    cycle(store, T0 + timedelta(minutes=61), monkeypatch)
    store.add_event("s16", "192.168.50.40", T0 + timedelta(minutes=64), T0 + timedelta(minutes=64, seconds=1))
    cycle(store, T0 + timedelta(minutes=65), monkeypatch)
    (only,) = sessions(store)
    assert only["event_count"] == 17  # not just the events inside "new event - timeout"


def test_late_event_with_old_timestamp_is_still_processed(monkeypatch):
    store = Store()
    store.add_event("x0", "192.168.50.50", T0, T0 + timedelta(seconds=1))
    cycle(store, T0 + timedelta(minutes=1), monkeypatch)
    # Shipped late by an agent that was offline: old @timestamp, new event.ingested.
    store.add_event("late", "192.168.50.60", T0 - timedelta(hours=3), T0 + timedelta(minutes=1, seconds=30))
    late = cycle(store, T0 + timedelta(minutes=2), monkeypatch)
    assert late["new_events"] == 1 and any(s["source_ip"] == "192.168.50.60" for s in sessions(store))


def test_backlog_drains_in_batches_without_skipping(monkeypatch):
    store = Store()
    for i in range(25):
        store.add_event(f"k{i:02d}", f"192.168.51.{i}", T0 + timedelta(seconds=i), T0 + timedelta(seconds=i + 1))
    seen = []
    now = T0 + timedelta(minutes=1)
    for _ in range(4):
        meta = cycle(store, now, monkeypatch, processing_batch_events=10)
        seen.append((meta["new_events"], meta.get("backlog", False)))
    assert [n for n, _ in seen][:3] == [10, 10, 5] and seen[0][1] and not seen[2][1]
    assert len(sessions(store)) == 25 and seen[3][0] == 0


def test_just_ingested_events_are_processed_with_default_settings(monkeypatch):
    """Regression: experiment finish() calls process_once right after settling, so an
    event ingested a moment ago must be materialized in that same cycle."""
    store = Store()
    now = T0 + timedelta(minutes=5)
    store.add_event("fresh", "192.168.50.70", now - timedelta(seconds=1), now - timedelta(milliseconds=200))
    processor = EventProcessor(store)
    original = processor.load_events
    processor.load_events = lambda: original(now)
    asyncio.run(processor.process_once())
    assert any(s["source_ip"] == "192.168.50.70" for s in sessions(store))


def test_overlap_rereads_events_that_became_visible_late(monkeypatch):
    store = Store()
    cycle(store, T0 + timedelta(minutes=1), monkeypatch, processing_overlap_seconds=30)
    # Stamped by Logstash before the watermark, but only searchable after that cycle ran.
    store.add_event("slow", "192.168.50.80", T0 + timedelta(seconds=50), T0 + timedelta(seconds=55))
    cycle(store, T0 + timedelta(minutes=1, seconds=10), monkeypatch, processing_overlap_seconds=30)
    assert any(s["source_ip"] == "192.168.50.80" for s in sessions(store))
