"""Every persona on 127.0.0.1 with remapped ports, driven by the real runner.

Used by the closed-loop scenario tests and by ``evaluation/measure_hardening.py``.
Nothing leaves loopback: personas bind 127.0.0.1 only and the runner's
``port_for`` is redirected to the local ports, so no scenario can reach the
network even if its manifest names a different port.
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "sensor/honeypots") not in sys.path:
    sys.path.insert(0, str(ROOT / "sensor/honeypots"))

import plugins  # noqa: E402,F401  (registers every protocol plugin)
from common import hardening as sensor_hardening  # noqa: E402
from common.persona import load_directory, parse_persona  # noqa: E402
from common.plugin import REGISTRY  # noqa: E402
from common.runtime import serve_persona, stop_servers  # noqa: E402

from attacks.runner import ot_it  # noqa: E402
from attacks.runner import run as runner  # noqa: E402
from backend.app.services.normalizer import normalize  # noqa: E402

UDP_SERVICES = frozenset({"coap", "ssdp", "dns"}) | ot_it.UDP
SENSOR_IP = "192.168.50.10"
LOCAL = "127.0.0.1"


def _free(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind((LOCAL, 0))
        return probe.getsockname()[1]


class _NoPacing:
    """Stands in for the runner's ``time`` module only (never the global one)."""

    @staticmethod
    def sleep(seconds: float) -> None:
        return None


class InProcessLab:
    def __init__(self, log_dir: Path) -> None:
        self.log_dir = Path(log_dir)
        self.portmap: dict[tuple[str, int], int] = {}
        self.files: list[Path] = []
        self.threads: list[Any] = []

    def start(self) -> InProcessLab:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        for persona in load_directory(ROOT / "sensor/honeypots/personas").values():
            doc = json.loads(json.dumps(persona.source))
            for service in doc["services"]:
                transport = REGISTRY[service["plugin"]].transport
                local = _free(socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)
                public = service.get("public_port", service["port"])
                self.portmap[(transport, public)] = local
                service["port"], service["public_port"] = local, public
            log = self.log_dir / f"{persona.id}.jsonl"
            self.files.append(log)
            threads, _ = serve_persona(parse_persona(doc), log_path=str(log), sensor_ip=SENSOR_IP, host=LOCAL)
            self.threads += threads
        return self

    def stop(self) -> None:
        stop_servers(self.threads)
        self.threads = []

    def port_for(self, step: dict[str, Any]) -> int:
        public = int(step.get("port", runner.PORTS[step["service"]]))
        transport = "udp" if step["service"] in UDP_SERVICES else "tcp"
        return self.portmap[(transport, public)]

    def run(self, doc: dict[str, Any], *, effects: tuple[str, ...] = (), decision_id: str | None = None) -> tuple[list[str], list[dict[str, Any]]]:
        """Run one scenario's steps; return (step statuses, normalized events).

        ``effects`` are enforced for the attacker (loopback) exactly as the sensor
        enforces an RL hardening decision.
        """
        offsets = {f: (f.stat().st_size if f.exists() else 0) for f in self.files}
        original_port_for, original_time = runner.port_for, runner.time
        runner.port_for = self.port_for
        runner.time = _NoPacing()  # skip the runner's own pauses; sensor tarpit delays stay real
        sensor_hardening._apply({LOCAL: {"level": "locked", "actions": list(effects), "decision_id": decision_id}} if effects else {})
        statuses = []
        try:
            for step in doc["steps"]:
                try:
                    runner.execute(LOCAL, step)
                    statuses.append("completed")
                except runner.ExpectedRejection:
                    statuses.append("rejected")
                except OSError:
                    statuses.append("failed")  # e.g. quarantine withheld a UDP reply or closed a socket
        finally:
            runner.port_for, runner.time = original_port_for, original_time
            sensor_hardening._apply({})
        events = []
        for log in self.files:
            if log.exists():
                with log.open(encoding="utf-8") as stream:
                    stream.seek(offsets[log])
                    events += [json.loads(line) for line in stream if line.strip()]
        normalized = [normalize({**e, "destination_ip": SENSOR_IP}, e["honeypot_type"], e["honeypot_id"], "pi-01") for e in events]
        return statuses, normalized
