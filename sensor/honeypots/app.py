"""Entrypoint: run one declarative device persona (``PERSONA=<id>``).

The persona is loaded from ``PERSONA_DIR`` (default ``/app/personas``); with
``PERSONA_FROM_BACKEND=true`` the backend's active version is fetched first and
the baked-in TOML is the fallback. Services, heartbeats and the posture/hardening
poller all run on daemon threads.
"""

import os
import threading

from common.hardening import start_posture_poller
from common.heartbeat import start_heartbeat
from common.persona import load_effective
from common.runtime import serve_persona


def main() -> None:
    persona_id = os.environ.get("PERSONA")
    if not persona_id:
        raise SystemExit("PERSONA is required (e.g. PERSONA=industrial-plc)")
    start_posture_poller()
    directory = os.getenv("PERSONA_DIR", "/app/personas")
    backend = os.getenv("BACKEND_URL") if os.getenv("PERSONA_FROM_BACKEND", "false").lower() in {"1", "true", "yes"} else None
    persona, origin = load_effective(persona_id, directory, url=backend, api_key=os.getenv("SENSOR_API_KEY"))
    print(f"trapsig persona {persona.id} v{persona.version} ({origin}) sha256={persona.content_sha256()[:12]}", flush=True)
    threads, telemetry = [], None
    if persona.enabled:
        threads, telemetry = serve_persona(persona, log_path=os.getenv("LOG_PATH", f"/logs/{persona.id}.jsonl"), sensor_ip=os.getenv("SENSOR_IP"))
    else:
        print(f"persona {persona.id} is disabled; reporting heartbeats only", flush=True)
    start_heartbeat(persona, origin, telemetry, threads)
    threading.Event().wait()


if __name__ == "__main__":
    main()
