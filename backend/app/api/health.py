from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..config import get_settings
from ..elastic import store
from ..services import processor as processor_module
from ..services.pi_manager import pi_manager

router = APIRouter()


@router.get("/health")
async def health():
    try:
        elastic = (await store.health()).get("status", "unknown")
    except Exception:
        elastic = "unavailable"
    return {"backend": "healthy", "elasticsearch": elastic}


@router.get("/health/live")
async def liveness():
    """Liveness: the process is up and serving (no dependency checks)."""
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness():
    """Readiness: Elasticsearch is reachable, so the API can serve data."""
    try:
        status = (await store.health()).get("status", "unknown")
        ready = status in {"green", "yellow"}
    except Exception:
        ready = False
    return JSONResponse({"status": "ready" if ready else "not-ready", "elasticsearch": ready}, status_code=200 if ready else 503)


@router.get("/system/status")
async def status():
    cfg = get_settings()
    data = await health()
    statuses = await pi_manager.statuses()

    async def count(index: str) -> int:
        return await store.count(index, missing_index_is_empty=True)

    return {
        **data,
        "logstash": "configured",
        "kibana_url": cfg.kibana_url,
        "pi": "reachable" if any(value != "unreachable" for value in statuses.values()) else "unreachable",
        "honeypots": statuses,
        "counts": {
            "events": await count("trapsig-events-*"),
            "sessions": await count("trapsig-sessions"),
            "detections": await count("trapsig-detections"),
            "experiments": await count("trapsig-experiments"),
            "dead_letter": await count("trapsig-dead-letter-*"),
        },
        "processor": processor_module.processor.status() if processor_module.processor else {"last_run": None},
    }
