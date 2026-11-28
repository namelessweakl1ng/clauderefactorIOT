"""Persona management API (create, edit, enable/disable, inspect deployment drift)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from ..elastic import store
from ..security import principal_of
from ..services import personas as svc
from .sensors import INSTANCES_INDEX, instance_status

router = APIRouter(prefix="/personas", tags=["personas"])


class PersonaDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    definition: dict[str, Any]
    note: str | None = Field(default=None, max_length=500)


class PersonaState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    note: str | None = Field(default=None, max_length=500)


async def _deployments() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for document in await store.search(INSTANCES_INDEX, size=500, sort_field="received_at", missing_index_is_empty=True):
        out.setdefault(document.get("persona_id"), []).append(
            {
                "sensor_id": document.get("sensor_id"),
                "status": instance_status(document),
                "running_sha256": (document.get("persona") or {}).get("content_sha256"),
                "running_version": (document.get("persona") or {}).get("version"),
                "received_at": document.get("received_at"),
            }
        )
    return out


def _invalid(exc: Exception) -> HTTPException:
    return HTTPException(422, str(exc))


@router.get("/plugins")
async def plugins() -> list[dict[str, Any]]:
    return svc.plugin_catalog()


@router.get("")
async def personas() -> list[dict[str, Any]]:
    deployments = await _deployments()
    ids = set(svc.seeds())
    ids |= {doc.get("persona_id") for doc in await svc.stored_versions(store) if doc.get("persona_id")}
    out = []
    for persona_id in sorted(ids):
        persona, origin, history = await svc.effective(store, persona_id)
        sha = persona.content_sha256()
        deployed = deployments.get(persona_id, [])
        out.append(
            {
                **persona.summary(),
                "origin": origin,
                "stored_versions": len(history),
                "deployments": [{**d, "in_sync": d["running_sha256"] == sha} for d in deployed],
            }
        )
    return out


@router.post("/validate")
async def validate(payload: PersonaDefinition) -> dict[str, Any]:
    try:
        persona = svc.validator().parse_persona(payload.definition)
    except ValueError as exc:
        raise _invalid(exc) from exc
    return {"valid": True, "summary": persona.summary()}


@router.get("/{persona_id}")
async def persona(persona_id: str) -> dict[str, Any]:
    try:
        current, origin, history = await svc.effective(store, persona_id)
    except KeyError as exc:
        raise HTTPException(404, "unknown persona") from exc
    deployments = (await _deployments()).get(persona_id, [])
    sha = current.content_sha256()
    return {
        "summary": current.summary(),
        "definition": current.source,
        "origin": origin,
        "history": [{k: doc.get(k) for k in ("version", "content_sha256", "enabled", "saved_at", "saved_by", "note")} for doc in history],
        "deployments": [{**d, "in_sync": d["running_sha256"] == sha} for d in deployments],
    }


@router.get("/{persona_id}/effective")
async def effective(persona_id: str) -> dict[str, Any]:
    """What a sensor should run (sensor role may read this)."""
    try:
        current, origin, _ = await svc.effective(store, persona_id)
    except KeyError as exc:
        raise HTTPException(404, "unknown persona") from exc
    return {"definition": current.source, "version": current.version, "content_sha256": current.content_sha256(), "origin": origin}


@router.put("/{persona_id}")
async def update(persona_id: str, payload: PersonaDefinition, request: Request) -> dict[str, Any]:
    if payload.definition.get("id") != persona_id:
        raise HTTPException(422, "definition id must match the URL")
    try:
        document = await svc.save_version(store, payload.definition, actor=principal_of(request).name, note=payload.note)
    except ValueError as exc:
        raise _invalid(exc) from exc
    return {**document, "deploy_hint": "restart the persona container (or sensor) to apply; deployments show in_sync=false until then"}


@router.post("/{persona_id}/state")
async def set_state(persona_id: str, payload: PersonaState, request: Request) -> dict[str, Any]:
    try:
        current, _, _ = await svc.effective(store, persona_id)
    except KeyError as exc:
        raise HTTPException(404, "unknown persona") from exc
    definition = {**current.source, "enabled": payload.enabled}
    try:
        return await svc.save_version(store, definition, actor=principal_of(request).name, note=payload.note or ("enabled" if payload.enabled else "disabled"))
    except ValueError as exc:
        raise _invalid(exc) from exc
