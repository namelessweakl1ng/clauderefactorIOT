from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .api import (
    adaptation,
    analytics,
    audit,
    detection,
    detections,
    evaluation,
    events,
    experiments,
    fleet,
    health,
    honeypots,
    metrics,
    network,
    personas,
    scenarios,
    sensors,
    sessions,
    stream,
)
from .config import get_settings
from .elastic import store
from .logging_config import configure_logging
from .security import security_middleware
from .services.processor import configure_processor

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    processor = configure_processor(store)
    processor.start()
    yield
    await processor.stop()
    await store.close()


app = FastAPI(title="TRAPSIG API", version="2.0.0", lifespan=lifespan)


@app.middleware("http")
async def security(request: Request, call_next):
    """Authenticate (role-based API keys), authorize via the policy table, audit writes.

    See ``backend/app/security.py``. Keys are read at request time so they can be
    enabled or rotated without restarting the API.
    """
    return await security_middleware(request, call_next, store)


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins.split(","),
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Content-Type", "X-API-Key"],
)
for router in [
    health.router,
    analytics.router,
    events.router,
    sessions.router,
    detections.router,
    detection.router,
    experiments.router,
    experiments.lab,
    evaluation.router,
    honeypots.router,
    scenarios.router,
    adaptation.router,
    metrics.router,
    sensors.router,
    fleet.router,
    personas.router,
    network.router,
    stream.router,
    audit.router,
]:
    app.include_router(router)
