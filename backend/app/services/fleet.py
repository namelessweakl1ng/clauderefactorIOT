"""Central fleet management: which personas each sensor device runs.

Assignments are versioned documents in ``trapsig-fleet`` (one per sensor),
seeded from ``sensor/fleet.toml``. Sensor agents poll
``GET /fleet/{sensor_id}/assignment`` and receive the *complete* persona
definitions they must run, so a device needs nothing but the backend URL, its
sensor ID and a sensor-role key. An assignment is only accepted if every persona
exists and no two services collide on the same (bind IP, transport, port).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import personas as persona_service

FLEET_INDEX = "trapsig-fleet"
_REPO = Path(__file__).resolve().parents[3]


class FleetError(ValueError):
    """The assignment is invalid; the message says why."""


def seed_path() -> Path:
    return Path(os.getenv("FLEET_SEED", str(_REPO / "sensor" / "fleet.toml")))


def seeds() -> dict[str, dict[str, Any]]:
    path = seed_path()
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {s["sensor_id"]: {**s, "version": 0, "origin": "seed"} for s in data.get("sensors", []) if s.get("sensor_id")}


def _bind(entry: dict[str, Any]) -> str:
    return str(entry.get("bind_ip") or "*")


def validate(assignment: dict[str, Any], available: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the normalized persona list or raise :class:`FleetError`."""
    entries = assignment.get("personas")
    if not isinstance(entries, list):
        raise FleetError("personas must be a list")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    ports: dict[tuple[str, str, int], str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("persona_id"):
            raise FleetError("each persona entry needs a persona_id")
        pid = str(entry["persona_id"])
        if pid not in available:
            raise FleetError(f"unknown persona {pid!r}")
        if pid in seen:
            raise FleetError(f"persona {pid!r} is assigned twice")
        seen.add(pid)
        bind_ip = entry.get("bind_ip") or None
        if bind_ip:
            try:
                address = ipaddress.ip_address(bind_ip)
            except ValueError as exc:
                raise FleetError(f"{pid}: bind_ip {bind_ip!r} is not an IP address") from exc
            if address.is_loopback:
                raise FleetError(f"{pid}: loopback bind addresses are excluded from analysis")
        enabled = bool(entry.get("enabled", True))
        normalized.append({"persona_id": pid, "bind_ip": bind_ip, "enabled": enabled})
        if not enabled:
            continue
        for service in available[pid].summary()["services"]:
            if not service["enabled"]:
                continue
            key = (_bind(entry), service["transport"], service["public_port"])
            # A wildcard bind collides with every specific address on the host.
            clashes = [k for k in ports if k[1:] == key[1:] and (k[0] == key[0] or "*" in (k[0], key[0]))]
            if clashes:
                other = ports[clashes[0]]
                raise FleetError(f"port conflict: {pid}:{service['name']} and {other} both use {service['transport']}/{service['public_port']} on {key[0]}")
            ports[key] = f"{pid}:{service['name']}"
    return normalized


def fingerprint(assignment: dict[str, Any], definitions: dict[str, Any]) -> str:
    material = json.dumps({"personas": assignment["personas"], "definitions": {k: v.get("content_sha256") for k, v in definitions.items()}}, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()[:16]


async def stored(store: Any) -> dict[str, dict[str, Any]]:
    try:
        documents = await store.search(FLEET_INDEX, size=500, sort_field="updated_at", missing_index_is_empty=True)
    except TypeError:
        documents = await store.search(FLEET_INDEX, size=500, sort_field="updated_at")
    return {d["sensor_id"]: {**d, "origin": "stored"} for d in documents if d.get("sensor_id")}


async def assignments(store: Any) -> dict[str, dict[str, Any]]:
    return {**seeds(), **await stored(store)}


async def effective_assignment(store: Any, sensor_id: str) -> dict[str, Any]:
    """Assignment plus full persona definitions for one sensor (what the agent runs)."""
    assignment = (await assignments(store)).get(sensor_id)
    if assignment is None:
        raise KeyError(sensor_id)
    definitions: dict[str, Any] = {}
    for entry in assignment.get("personas", []):
        persona, origin, _ = await persona_service.effective(store, entry["persona_id"])
        definitions[entry["persona_id"]] = {
            "definition": persona.source,
            "version": persona.version,
            "content_sha256": persona.content_sha256(),
            "origin": origin,
        }
    return {
        "sensor_id": sensor_id,
        "label": assignment.get("label"),
        "os": assignment.get("os"),
        "personas": assignment.get("personas", []),
        "definitions": definitions,
        "assignment_version": assignment.get("version", 0),
        "fingerprint": fingerprint(assignment, definitions),
        "origin": assignment.get("origin"),
    }


async def save(store: Any, sensor_id: str, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    available = {pid: (await persona_service.effective(store, pid))[0] for pid in await _persona_ids(store)}
    personas = validate(payload, available)
    current = (await assignments(store)).get(sensor_id, {})
    document = {
        "sensor_id": sensor_id,
        "label": str(payload.get("label") or current.get("label") or sensor_id)[:80],
        "os": str(payload.get("os") or current.get("os") or "any")[:24],
        "personas": personas,
        "version": int(current.get("version", 0)) + 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_by": actor,
    }
    await store.save(FLEET_INDEX, sensor_id, document)
    return document


async def _persona_ids(store: Any) -> set[str]:
    ids = set(persona_service.seeds())
    ids |= {str(d["persona_id"]) for d in await persona_service.stored_versions(store) if d.get("persona_id")}
    return ids
