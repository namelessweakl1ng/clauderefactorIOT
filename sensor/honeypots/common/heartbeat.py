"""Sensor heartbeat agent (stdlib only, fail-open).

Every ``HEARTBEAT_INTERVAL`` seconds a daemon thread POSTs the persona summary,
per-service liveness and counters, and process resource usage to the backend's
``/sensors/heartbeat`` with the sensor-role API key. Failures are swallowed:
telemetry delivery (Filebeat) is independent, and an unreachable backend must
never affect the decoys.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any

AGENT_VERSION = "2.0"


def _proc_rss_bytes() -> int | None:
    try:
        with open("/proc/self/status", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _loadavg() -> list[float] | None:
    try:
        with open("/proc/loadavg", encoding="ascii") as stream:
            return [float(x) for x in stream.read().split()[:3]]
    except (OSError, ValueError):
        return None


def tcp_listening(port: int, timeout: float = 0.5) -> bool:
    try:
        # Containers listen on all interfaces; a host-run sensor may bind one address.
        with socket.create_connection((os.getenv("HEARTBEAT_PROBE_HOST", "127.0.0.1"), port), timeout=timeout):
            return True
    except OSError:
        return False


def build_payload(persona: Any, origin: str, telemetry: Any, threads: list[threading.Thread], started: float, *, probe: bool = True) -> dict[str, Any]:
    alive = {thread.name.split(":", 1)[-1]: thread.is_alive() for thread in threads}
    stats = telemetry.snapshot() if telemetry is not None else {}
    services = []
    for binding in persona.bindings() if persona.enabled else []:
        name = binding.service_name
        transport = binding.plugin.transport
        # TCP: real local connect probe (such probes are loopback and are filtered
        # from analytics by the pipeline); UDP: the server thread must be alive.
        listening = alive.get(name, False) and (not probe or transport != "tcp" or tcp_listening(binding.port))
        services.append(
            {
                "name": name,
                "plugin": binding.plugin.name,
                "protocol": binding.plugin.protocol,
                "transport": transport,
                "port": binding.port,
                "public_port": binding.public_port,
                "listening": bool(listening),
                **stats.get(name, {"events": 0, "errors": 0, "last_event_at": None}),
            }
        )
    return {
        "sensor_id": os.getenv("SENSOR_ID") or socket.gethostname(),
        "hostname": os.getenv("HONEYPOT_HOSTNAME") or socket.gethostname(),
        "sensor_ip": os.getenv("SENSOR_IP") or None,
        "agent_version": AGENT_VERSION,
        "schema_version": 2,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": round(time.monotonic() - started, 1),
        "persona": persona.summary(),
        "persona_origin": origin,
        "services": services,
        "process": {"rss_bytes": _proc_rss_bytes(), "threads": threading.active_count(), "loadavg": _loadavg()},
    }


def start_heartbeat(persona: Any, origin: str, telemetry: Any, threads: list[threading.Thread], *, stop: threading.Event | None = None) -> threading.Event:
    stop = stop or threading.Event()
    backend = os.getenv("BACKEND_URL", "").rstrip("/")
    if not backend:
        return stop
    url = f"{backend}/sensors/heartbeat"
    interval = float(os.getenv("HEARTBEAT_INTERVAL", "30"))
    api_key = os.getenv("SENSOR_API_KEY", "")
    started = time.monotonic()

    def loop() -> None:
        while not stop.is_set():
            try:
                # The TCP connect probe is itself a honeypot interaction; it must come
                # from loopback (as in containers) or be disabled, or it pollutes analysis.
                probe = os.getenv("HEARTBEAT_TCP_PROBE", "1").lower() not in {"0", "false", "no"}
                body = json.dumps(build_payload(persona, origin, telemetry, threads, started, probe=probe)).encode()
                headers = {"Content-Type": "application/json", "User-Agent": f"trapsig-sensor/{AGENT_VERSION}"}
                if api_key:
                    headers["X-API-Key"] = api_key
                request = urllib.request.Request(url, data=body, headers=headers, method="POST")
                urllib.request.urlopen(request, timeout=3).close()  # noqa: S310 - fixed lab backend URL
            except Exception:
                pass
            stop.wait(interval)

    threading.Thread(target=loop, name="heartbeat", daemon=True).start()
    return stop
