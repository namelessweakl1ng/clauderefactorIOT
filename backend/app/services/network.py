"""Passive network intelligence: Zeek flows correlated with honeypot telemetry.

Zeek (optional ``netmon`` profile on the sensor) logs ``conn``/``dns``/``http``/
``ssl`` as JSON; Logstash normalizes them into ``trapsig-network-*``. Both Zeek
and the TRAPSIG sensor emit **Community ID v1**, so correlation is an exact join
on ``network.community_id`` -- no time-window/port heuristics.

What the join gives a researcher:

* **coverage**: the fraction of honeypot interactions whose flow Zeek also saw
  (pipeline health and a check that the sensor's view is complete);
* **flow context** for a session: bytes, packets, duration, Zeek connection state
  and history string;
* **network-only activity**: flows from a source that never produced a honeypot
  event (e.g. SYN scans of closed ports, ``conn_state`` S0/REJ) -- reconnaissance
  that the application-layer decoys cannot see.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

NETWORK_INDEX = "trapsig-network-*"
# Zeek conn_state values that indicate probing rather than a completed exchange.
SCAN_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


def community_ids(events: Iterable[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for event in events:
        value = (event.get("network") or {}).get("community_id")
        if value and value not in seen:
            seen.append(value)
    return seen


def correlate(events: list[dict[str, Any]], flows: list[dict[str, Any]]) -> dict[str, Any]:
    """Join honeypot events and Zeek flows on Community ID."""
    # dns/http/ssl records carry only Zeek's uid; inherit the conn record's
    # Community ID through it.
    uid_to_cid = {
        (f.get("zeek") or {}).get("uid"): (f.get("network") or {}).get("community_id")
        for f in flows
        if (f.get("zeek") or {}).get("uid") and (f.get("network") or {}).get("community_id")
    }
    resolved = []
    for flow in flows:
        if not (flow.get("network") or {}).get("community_id") and (flow.get("zeek") or {}).get("uid") in uid_to_cid:
            flow = {**flow, "network": {**(flow.get("network") or {}), "community_id": uid_to_cid[flow["zeek"]["uid"]]}}
        resolved.append(flow)
    flows = resolved
    by_flow: dict[str, list[dict[str, Any]]] = {}
    for flow in flows:
        key = (flow.get("network") or {}).get("community_id")
        if key:
            by_flow.setdefault(key, []).append(flow)
    keyed = [e for e in events if (e.get("network") or {}).get("community_id")]
    matched_events = [e for e in keyed if e["network"]["community_id"] in by_flow]
    event_keys = {e["network"]["community_id"] for e in keyed}
    unmatched_flows = [f for f in flows if (f.get("network") or {}).get("community_id") not in event_keys]
    pairs = []
    for key in sorted({str(e["network"]["community_id"]) for e in matched_events}):
        conn = next((f for f in by_flow[key] if (f.get("event") or {}).get("dataset") == "zeek.conn"), by_flow[key][0])
        pairs.append(
            {
                "community_id": key,
                "event_ids": [(e.get("event") or {}).get("id") for e in matched_events if e["network"]["community_id"] == key],
                "zeek_uid": (conn.get("zeek") or {}).get("uid"),
                "conn_state": (conn.get("zeek") or {}).get("conn_state"),
                "history": (conn.get("zeek") or {}).get("history"),
                "duration": (conn.get("zeek") or {}).get("duration"),
                "orig_bytes": (conn.get("zeek") or {}).get("orig_bytes"),
                "resp_bytes": (conn.get("zeek") or {}).get("resp_bytes"),
                "datasets": sorted({str((f.get("event") or {}).get("dataset")) for f in by_flow[key] if (f.get("event") or {}).get("dataset")}),
            }
        )
    return {
        "honeypot_events": len(events),
        "events_with_community_id": len(keyed),
        "events_matched": len(matched_events),
        "coverage": (len(matched_events) / len(keyed)) if keyed else None,
        "flows": len(flows),
        "flows_without_honeypot_event": len(unmatched_flows),
        "pairs": pairs,
        "network_only": summarize_flows(unmatched_flows),
    }


def summarize_flows(flows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-source statistics over flows (scan indicators included)."""
    sources: dict[str, dict[str, Any]] = {}
    for flow in flows:
        source = (flow.get("source") or {}).get("ip")
        if not source:
            continue
        zeek = flow.get("zeek") or {}
        entry = sources.setdefault(source, {"source_ip": source, "flows": 0, "ports": set(), "states": Counter(), "bytes": 0})
        entry["flows"] += 1
        port = (flow.get("destination") or {}).get("port")
        if port is not None:
            entry["ports"].add(port)
        if zeek.get("conn_state"):
            entry["states"][zeek["conn_state"]] += 1
        entry["bytes"] += int(zeek.get("orig_bytes") or 0) + int(zeek.get("resp_bytes") or 0)
    out = []
    for entry in sources.values():
        scan_like = sum(count for state, count in entry["states"].items() if state in SCAN_STATES)
        out.append(
            {
                "source_ip": entry["source_ip"],
                "flows": entry["flows"],
                "distinct_destination_ports": len(entry["ports"]),
                "destination_ports": sorted(entry["ports"])[:50],
                "conn_states": dict(entry["states"]),
                "scan_like_flows": scan_like,
                "scan_like_ratio": scan_like / entry["flows"] if entry["flows"] else 0.0,
                "bytes": entry["bytes"],
                "likely_port_scan": len(entry["ports"]) >= 10 and scan_like / max(1, entry["flows"]) >= 0.5,
            }
        )
    out.sort(key=lambda item: (-item["distinct_destination_ports"], -item["flows"]))
    return {"sources": out, "likely_port_scanners": [s["source_ip"] for s in out if s["likely_port_scan"]]}
