"""Sensor fleet: authenticated heartbeats in, computed health out.

One document per (sensor, persona instance) in ``trapsig-sensor-instances`` -- so
several persona containers on one Pi never overwrite each other -- aggregated
per sensor on read. Health is derived, never self-reported: ``online`` when the
newest heartbeat is younger than ``3 × SENSOR_HEARTBEAT_INTERVAL``, ``degraded``
when online but a declared service is not listening, otherwise ``offline``.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..elastic import store

router = APIRouter(prefix="/sensors", tags=["sensors"])
INSTANCES_INDEX = "trapsig-sensor-instances"


class ServiceHealth(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = Field(max_length=64)
    plugin: str = Field(max_length=64)
    protocol: str | None = Field(default=None, max_length=32)
    transport: str = Field(max_length=8)
    port: int = Field(ge=0, le=65535)
    public_port: int = Field(ge=0, le=65535)
    listening: bool
    events: int = Field(default=0, ge=0)
    errors: int = Field(default=0, ge=0)
    last_event_at: str | None = None


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sensor_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._\-]+$")
    hostname: str | None = Field(default=None, max_length=120)
    sensor_ip: str | None = Field(default=None, max_length=64)
    agent_version: str | None = Field(default=None, max_length=32)
    schema_version: int | None = None
    sent_at: str | None = None
    uptime_seconds: float | None = Field(default=None, ge=0)
    persona: dict[str, Any]
    persona_origin: str | None = Field(default=None, max_length=16)
    services: list[ServiceHealth] = Field(default_factory=list, max_length=64)
    process: dict[str, Any] = Field(default_factory=dict)


def _interval() -> float:
    return float(os.getenv("SENSOR_HEARTBEAT_INTERVAL", "30"))


def _parse(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def instance_status(document: dict[str, Any], now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    seen = _parse(document.get("received_at"))
    if seen is None or (now - seen).total_seconds() > 3 * _interval():
        return "offline"
    if not document.get("persona", {}).get("enabled", True):
        return "disabled"
    services = document.get("services") or []
    return "degraded" if any(not s.get("listening") for s in services) else "online"


@router.post("/heartbeat", status_code=202)
async def heartbeat(payload: Heartbeat) -> dict[str, Any]:
    persona_id = str(payload.persona.get("id") or "unknown")[:64]
    identifier = "SIN-" + sha256(f"{payload.sensor_id}|{persona_id}".encode()).hexdigest()[:16]
    document = {
        **payload.model_dump(mode="json"),
        "persona_id": persona_id,
        "instance_id": identifier,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
    await store.save(INSTANCES_INDEX, identifier, document, refresh=False)
    return {"accepted": True, "instance_id": identifier}


def aggregate(instances: list[dict[str, Any]], now: datetime | None = None) -> list[dict[str, Any]]:
    sensors: dict[str, dict[str, Any]] = {}
    for document in instances:
        status = instance_status(document, now)
        sensor = sensors.setdefault(
            document["sensor_id"],
            {
                "sensor_id": document["sensor_id"],
                "hostname": document.get("hostname"),
                "sensor_ip": document.get("sensor_ip"),
                "instances": [],
                "last_seen": None,
            },
        )
        services = document.get("services") or []
        sensor["instances"].append(
            {
                "instance_id": document.get("instance_id"),
                "persona_id": document.get("persona_id"),
                "persona_name": document.get("persona", {}).get("name"),
                "persona_version": document.get("persona", {}).get("version"),
                "persona_sha256": document.get("persona", {}).get("content_sha256"),
                "persona_origin": document.get("persona_origin"),
                "status": status,
                "received_at": document.get("received_at"),
                "uptime_seconds": document.get("uptime_seconds"),
                "services": services,
                "process": document.get("process") or {},
            }
        )
        if not sensor["last_seen"] or str(document.get("received_at")) > sensor["last_seen"]:
            sensor["last_seen"] = document.get("received_at")
    for sensor in sensors.values():
        live = [i["status"] for i in sensor["instances"] if i["status"] != "offline"]
        if not live:
            sensor["status"] = "offline"
        elif all(status == "disabled" for status in live):
            sensor["status"] = "disabled"
        elif all(status in {"online", "disabled"} for status in live):
            sensor["status"] = "online"
        else:
            sensor["status"] = "degraded"
        all_services = [s for i in sensor["instances"] if i["status"] != "offline" for s in i["services"]]
        sensor["services_total"] = len(all_services)
        sensor["services_listening"] = sum(bool(s.get("listening")) for s in all_services)
        sensor["events_total"] = sum(int(s.get("events") or 0) for s in all_services)
    return sorted(sensors.values(), key=lambda s: s["sensor_id"])


@router.get("")
async def sensors() -> list[dict[str, Any]]:
    instances = await store.search(INSTANCES_INDEX, size=500, sort_field="received_at", missing_index_is_empty=True)
    return aggregate(instances)


@router.get("/{sensor_id}")
async def sensor(sensor_id: str) -> dict[str, Any]:
    for item in await sensors():
        if item["sensor_id"] == sensor_id:
            return item
    raise HTTPException(404, "unknown sensor")
