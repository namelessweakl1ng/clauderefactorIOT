"""Versioned persona management backed by the sensor's own validator.

The single persona validator lives in the sensor package
(``sensor/honeypots/common/persona.py``); the backend imports it from
``PERSONA_RUNTIME_PATH`` (a read-only mount in Compose) so a persona the API
accepts is exactly one the sensor can run. Seeds are the TOML files baked into
the sensor image; every API edit appends an immutable version document to
``trapsig-personas``. The *effective* persona is the newest stored version, or
the seed when none exists. Sensors fetch it at start (``PERSONA_FROM_BACKEND``),
so deployment = save, then restart the persona container. Drift is visible:
heartbeats report the content hash actually running.
"""

from __future__ import annotations

import importlib
import os
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

PERSONA_INDEX = "trapsig-personas"
_REPO = Path(__file__).resolve().parents[3]


def runtime_path() -> Path:
    return Path(os.getenv("PERSONA_RUNTIME_PATH", str(_REPO / "sensor" / "honeypots")))


def seed_dir() -> Path:
    return Path(os.getenv("PERSONA_DIR", str(runtime_path() / "personas")))


@lru_cache
def validator() -> Any:
    """Import the sensor's persona module (and plugin registry) once."""
    path = str(runtime_path())
    if path not in sys.path:
        sys.path.insert(0, path)
    return importlib.import_module("common.persona")


def plugin_catalog() -> list[dict[str, Any]]:
    validator()  # importing the persona module registers every plugin
    registry = importlib.import_module("common.plugin").REGISTRY
    out = []
    for name, cls in sorted(registry.items()):
        out.append(
            {
                "name": name,
                "protocol": cls.protocol,
                "transport": cls.transport,
                "interaction": cls.interaction,
                "default_port": cls.default_port,
                "max_messages_limit": cls.max_messages_limit,
                "description": (sys.modules[cls.__module__].__doc__ or "").strip().split("\n\n")[0],
            }
        )
    return out


def seeds() -> dict[str, Any]:
    directory = seed_dir()
    if not directory.exists():
        return {}
    return validator().load_directory(directory)


async def stored_versions(store: Any, persona_id: str | None = None) -> list[dict[str, Any]]:
    query = {"term": {"persona_id": persona_id}} if persona_id else None
    try:
        return await store.search(PERSONA_INDEX, query, size=500, sort_field="saved_at", missing_index_is_empty=True)
    except TypeError:
        return await store.search(PERSONA_INDEX, query, size=500, sort_field="saved_at")


async def effective(store: Any, persona_id: str) -> tuple[Any, str, list[dict[str, Any]]]:
    """Return (persona, origin, history) or raise KeyError."""
    history = [doc for doc in await stored_versions(store, persona_id) if doc.get("persona_id") == persona_id]
    history.sort(key=lambda doc: int(doc.get("version", 0)), reverse=True)
    if history:
        return validator().parse_persona(history[0]["definition"]), "stored", history
    seed = seeds().get(persona_id)
    if seed is None:
        raise KeyError(persona_id)
    return seed, "seed", []


async def save_version(store: Any, definition: dict[str, Any], *, actor: str, note: str | None = None) -> dict[str, Any]:
    persona_id = str(definition.get("id", ""))
    try:
        _, _, history = await effective(store, persona_id)
        current_version = int(history[0]["version"]) if history else int(seeds()[persona_id].version)
    except KeyError:
        current_version = 0
    definition = {**definition, "version": current_version + 1}
    persona = validator().parse_persona(definition)  # raises PersonaError
    document = {
        "persona_id": persona.id,
        "version": persona.version,
        "definition": persona.source,
        "content_sha256": persona.content_sha256(),
        "enabled": persona.enabled,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "saved_by": actor,
        "note": note,
    }
    await store.save(PERSONA_INDEX, f"{persona.id}:v{persona.version}", document)
    return document
