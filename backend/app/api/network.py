"""Network intelligence API: Zeek flows and their correlation with honeypot events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from ..elastic import store
from ..services.experiments import exact_filter
from ..services.network import NETWORK_INDEX, community_ids, correlate, summarize_flows

router = APIRouter(prefix="/network", tags=["network"])


def _window(minutes: int) -> dict[str, Any]:
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    return {"range": {"@timestamp": {"gte": since}}}


@router.get("/status")
async def status() -> dict[str, Any]:
    flows = await store.count(NETWORK_INDEX, missing_index_is_empty=True)
    return {"enabled": flows > 0, "flows_indexed": flows, "hint": None if flows else "start the sensor with `--profile netmon` to enable Zeek"}


@router.get("/summary")
async def summary(minutes: int = Query(60, ge=1, le=525600)) -> dict[str, Any]:
    window = _window(minutes)
    flows = await store.search(NETWORK_INDEX, {"bool": {"filter": [window]}}, size=5000, missing_index_is_empty=True)
    events = await store.search(
        "trapsig-events-*",
        {"bool": {"filter": [window, {"exists": {"field": "network.community_id"}}], "must_not": [{"term": {"trapsig.internal": True}}]}},
        size=5000,
        missing_index_is_empty=True,
    )
    result = correlate(events, flows)
    result["window_minutes"] = minutes
    result["sampled"] = len(flows) >= 5000 or len(events) >= 5000
    return result


@router.get("/flows")
async def flows(source_ip: str | None = None, minutes: int = Query(60, ge=1, le=525600), limit: int = Query(200, ge=1, le=2000)) -> list[dict[str, Any]]:
    filters = [_window(minutes)]
    if source_ip:
        filters.append(exact_filter("source.ip", source_ip))
    return await store.search(NETWORK_INDEX, {"bool": {"filter": filters}}, size=limit, missing_index_is_empty=True)


@router.get("/sessions/{session_id}")
async def session_flows(session_id: str) -> dict[str, Any]:
    session = await store.get("trapsig-sessions", session_id)
    if session is None:
        raise HTTPException(404, "unknown session")
    ids = session.get("event_ids") or []
    events = await store.search_all("trapsig-events-*", {"terms": {"event.id": ids[:1000]}}, missing_index_is_empty=True) if ids else []
    keys = community_ids(events)
    matched = await store.search(NETWORK_INDEX, {"terms": {"network.community_id": keys}}, size=2000, missing_index_is_empty=True) if keys else []
    window_flows = await store.search(
        NETWORK_INDEX,
        {
            "bool": {
                "filter": [
                    exact_filter("source.ip", session.get("source_ip")),
                    {"range": {"@timestamp": {"gte": session.get("start_time"), "lte": session.get("end_time")}}},
                ]
            }
        },
        size=2000,
        missing_index_is_empty=True,
    )
    result = correlate(events, matched)
    known = {(f.get("network") or {}).get("community_id") for f in matched}
    result["network_only_in_window"] = summarize_flows([f for f in window_flows if (f.get("network") or {}).get("community_id") not in known])
    result["session_id"] = session_id
    return result
