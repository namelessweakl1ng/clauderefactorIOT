"""Fleet API: central assignment of personas to sensor devices."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from ..elastic import store
from ..security import principal_of
from ..services import fleet as svc
from ..services import personas as persona_service
from .sensors import INSTANCES_INDEX, instance_status

router = APIRouter(prefix="/fleet", tags=["fleet"])


class PersonaSlot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    persona_id: str = Field(min_length=1, max_length=64)
    bind_ip: str | None = Field(default=None, max_length=64)
    enabled: bool = True


class Assignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str | None = Field(default=None, max_length=80)
    os: str | None = Field(default=None, max_length=24)
    personas: list[PersonaSlot] = Field(max_length=64)


@router.get("")
async def fleet() -> list[dict[str, Any]]:
    """Every known sensor: assignment, live status of each assigned persona, and drift."""
    assignments = await svc.assignments(store)
    instances = await store.search(INSTANCES_INDEX, size=1000, sort_field="received_at", missing_index_is_empty=True)
    live: dict[str, dict[str, dict[str, Any]]] = {}
    for doc in instances:
        live.setdefault(doc.get("sensor_id"), {})[doc.get("persona_id")] = doc
    out = []
    for sensor_id in sorted(set(assignments) | set(live)):
        assignment = assignments.get(sensor_id, {"personas": [], "origin": "unassigned"})
        running = live.get(sensor_id, {})
        slots = []
        for entry in assignment.get("personas", []):
            doc = running.get(entry["persona_id"])
            services = (doc or {}).get("services") or []
            slots.append(
                {
                    **entry,
                    "status": instance_status(doc) if doc else ("disabled" if not entry.get("enabled", True) else "not running"),
                    "services_listening": sum(bool(s.get("listening")) for s in services),
                    "services_total": len(services),
                    "events": sum(int(s.get("events") or 0) for s in services),
                }
            )
        unassigned = [pid for pid in running if pid not in {e["persona_id"] for e in assignment.get("personas", [])}]
        any_doc = next(iter(running.values()), {})
        out.append(
            {
                "sensor_id": sensor_id,
                "label": assignment.get("label"),
                "os": assignment.get("os"),
                "origin": assignment.get("origin"),
                "version": assignment.get("version", 0),
                "hostname": any_doc.get("hostname"),
                "sensor_ip": any_doc.get("sensor_ip"),
                "agent_version": any_doc.get("agent_version"),
                "last_seen": max((d.get("received_at") or "" for d in running.values()), default=None),
                "personas": slots,
                "running_but_unassigned": unassigned,
            }
        )
    return out


@router.get("/personas")
async def assignable_personas() -> list[dict[str, Any]]:
    out = []
    for pid in sorted(await svc._persona_ids(store)):
        persona, _, _ = await persona_service.effective(store, pid)
        summary = persona.summary()
        out.append(
            {
                "id": pid,
                "name": summary["name"],
                "device_type": summary["device_type"],
                "ports": [f"{s['transport']}/{s['public_port']}" for s in summary["services"]],
            }
        )
    return out


@router.get("/{sensor_id}/assignment")
async def assignment(sensor_id: str) -> dict[str, Any]:
    """What one sensor agent must run (sensor role may read this)."""
    try:
        return await svc.effective_assignment(store, sensor_id)
    except KeyError as exc:
        raise HTTPException(404, f"no assignment for sensor {sensor_id!r}; add it to sensor/fleet.toml or PUT /fleet/{sensor_id}") from exc


@router.put("/{sensor_id}")
async def update(sensor_id: str, payload: Assignment, request: Request) -> dict[str, Any]:
    if not sensor_id.replace("-", "").replace("_", "").replace(".", "").isalnum() or len(sensor_id) > 80:
        raise HTTPException(422, "invalid sensor_id")
    try:
        return await svc.save(store, sensor_id, payload.model_dump(), actor=principal_of(request).name)
    except svc.FleetError as exc:
        raise HTTPException(422, str(exc)) from exc
