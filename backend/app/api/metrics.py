"""Prometheus-compatible metrics exposition (stdlib only, no client dependency).

Gives operations a window into the pipeline beyond /system/status: event/derived
counts, dead-letter volume (the ingestion-health signal), processor liveness and
leadership, and the age of the active learned policy. Emitted in the Prometheus
text exposition format so any scraper or `curl` can read it.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Response

from ..elastic import store
from ..services import processor as processor_module
from ..services.ml.store import POLICY_INDEX

router = APIRouter()

_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _line(name: str, value, help_text: str, kind: str = "gauge") -> list[str]:
    if value is None:
        return []
    return [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}", f"{name} {value}"]


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


@router.get("/metrics")
async def metrics() -> Response:
    async def count(index: str) -> int:
        return await store.count(index, missing_index_is_empty=True)

    lines: list[str] = []
    for index, metric in (
        ("trapsig-events-*", "trapsig_events_total"),
        ("trapsig-sessions", "trapsig_sessions_total"),
        ("trapsig-detections", "trapsig_detections_total"),
        ("trapsig-experiments", "trapsig_experiments_total"),
        ("trapsig-dead-letter-*", "trapsig_dead_letter_total"),
        ("trapsig-hardening-decisions", "trapsig_hardening_decisions_total"),
    ):
        try:
            lines += _line(metric, await count(index), f"Document count for {index}")
        except Exception:
            continue

    processor = processor_module.processor
    if processor is not None:
        status = processor.status()
        lines += _line("trapsig_processor_sessions_written", status.get("sessions_written"), "Sessions written in the last cycle")
        lines += _line("trapsig_processor_detections_written", status.get("detections_written"), "Detections written in the last cycle")
        lines += _line("trapsig_processor_hardening_transitions", status.get("hardening_transitions"), "Hardening decisions made in the last cycle")
        lines += _line("trapsig_processor_is_leader", int(bool(status.get("is_leader"))), "1 when this replica is the active writer")
        last_run = _parse_time(status.get("last_run"))
        if last_run is not None:
            age = (datetime.now(timezone.utc) - last_run).total_seconds()
            lines += _line("trapsig_processor_last_run_age_seconds", round(age, 1), "Seconds since the last processor cycle")
        lines += _line("trapsig_processor_has_error", int(bool(status.get("last_error"))), "1 when the last cycle errored")

    try:
        policies = await store.search(POLICY_INDEX, size=1, sort_field="trained_at", missing_index_is_empty=True)
        trained = _parse_time(policies[0].get("trained_at")) if policies else None
        if trained is not None:
            lines += _line(
                "trapsig_active_policy_age_seconds",
                round((datetime.now(timezone.utc) - trained).total_seconds(), 1),
                "Seconds since the newest policy generation was trained",
            )
    except Exception:
        pass

    return Response("\n".join(lines) + "\n", media_type=_CONTENT_TYPE)
