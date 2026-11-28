"""Live operations stream (Server-Sent Events).

Pattern from T-Pot Attack Map's ``DataServer.py`` (poll Elasticsearch with a
watermark) without its Redis hop: each client gets its own watermark over
``event.ingested`` for telemetry and ``detected_at`` for detections, polled every
``STREAM_POLL_SECONDS``. IDs seen at the watermark instant are remembered so a
``gte`` range never re-emits or skips same-millisecond documents. Loopback
health probes are excluded exactly as analytics excludes them.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from ..elastic import store

router = APIRouter(prefix="/stream", tags=["stream"])
_FIELDS = (
    "@timestamp",
    "event",
    "source",
    "destination",
    "service",
    "network",
    "honeypot",
    "persona",
    "url",
    "mqtt",
    "modbus",
    "coap",
    "rtsp",
    "ftp",
    "dns",
    "ssdp",
    "authentication",
    "trapsig",
)


def _compact(document: dict[str, Any]) -> dict[str, Any]:
    out = {key: document[key] for key in _FIELDS if key in document}
    auth = out.get("authentication")
    if isinstance(auth, dict) and "password" in auth:
        out["authentication"] = {**auth, "password": "•••"}  # live view never shows secrets
    out["_id"] = document.get("_id")
    return out


async def _new(index: str, field: str, watermark: str, seen: set[str], extra_filter: list[dict[str, Any]]) -> list[dict[str, Any]]:
    query = {"bool": {"filter": [{"range": {field: {"gte": watermark}}}, *extra_filter], "must_not": [{"term": {"trapsig.internal": True}}]}}
    documents = await store.search(index, query, size=200, sort_field=field, missing_index_is_empty=True)
    return [doc for doc in reversed(documents) if doc.get("_id") not in seen]


def _advance(documents: list[dict[str, Any]], field_getter, watermark: str, seen: set[str]) -> tuple[str, set[str]]:
    for document in documents:
        value = field_getter(document)
        if not value:
            continue
        if value > watermark:
            watermark, seen = value, set()
        if value == watermark:
            seen.add(document.get("_id"))
    return watermark, seen


def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'), default=str)}\n\n"


async def event_stream(request: Request, lookback_seconds: int) -> AsyncIterator[str]:
    poll = float(os.getenv("STREAM_POLL_SECONDS", "2"))
    start = (datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)).isoformat()
    event_mark, event_seen = start, set()
    detection_mark, detection_seen = start, set()
    yield "retry: 5000\n\n"
    idle = 0.0
    while not await request.is_disconnected():
        try:
            events = await _new("trapsig-events-*", "event.ingested", event_mark, event_seen, [])
            detections = await _new("trapsig-detections", "detected_at", detection_mark, detection_seen, [])
        except Exception as exc:  # report and keep the connection
            yield _sse("error", {"detail": type(exc).__name__})
            await asyncio.sleep(poll * 3)
            continue
        for document in events:
            yield _sse("telemetry", _compact(document))
        for document in detections:
            yield _sse(
                "detection",
                {
                    k: document.get(k)
                    for k in ("detection_id", "type", "severity", "confidence", "source_ip", "session_id", "reason", "fired_by", "attack", "detected_at")
                },
            )
        event_mark, event_seen = _advance(events, lambda d: (d.get("event") or {}).get("ingested"), event_mark, event_seen)
        detection_mark, detection_seen = _advance(detections, lambda d: d.get("detected_at"), detection_mark, detection_seen)
        idle = 0.0 if events or detections else idle + poll
        if idle >= 15:
            yield _sse("heartbeat", {"at": datetime.now(timezone.utc).isoformat()})
            idle = 0.0
        await asyncio.sleep(poll)


@router.get("/events")
async def stream_events(request: Request, lookback_seconds: int = 60) -> StreamingResponse:
    lookback = max(0, min(lookback_seconds, 3600))
    return StreamingResponse(event_stream(request, lookback), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
