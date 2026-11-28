"""TRAPSIG sensor agent: one stdlib-only program for Pi OS Lite, Linux and Windows.

    python agent.py run     --config trapsig-sensor.toml
    python agent.py check   --config trapsig-sensor.toml   # validate, fetch assignment, show ports
    python agent.py install --config trapsig-sensor.toml   # print (or --apply) a systemd unit / Windows task

What it does
------------
* **Central assignment.** Polls ``GET /fleet/<sensor_id>/assignment`` on the
  backend and runs exactly the personas assigned to this device, each on its
  public ports, optionally on its own IP alias (``bind_ip``). A changed
  assignment is applied within one poll interval, without restarting the agent.
  The last good assignment is cached on disk, so decoys keep running when the
  backend is unreachable.
* **Telemetry shipping.** Persona events are written as JSONL to the data
  directory and shipped to the analysis host's Logstash HTTP input with
  persisted offsets (at-least-once delivery; event IDs make re-delivery
  idempotent). Extra logs (e.g. a Cowrie container's JSON log) can be shipped too.
* **Heartbeats and RL hardening** use the existing sensor modules.

Configuration (TOML; every key may also be given as an environment variable
``TRAPSIG_<KEY>`` in upper case)::

    sensor_id = "host-office"
    backend_url = "http://analysis.lan:8000"
    api_key = "<sensor-role key>"                 # API_KEYS entry "sensor:<key>"
    ingest_url = "http://analysis.lan:5045"      # Logstash HTTP input
    ingest_user = "trapsig"
    ingest_password = "<TRAPSIG_INGEST_PASSWORD>"
    # sensor_ip = "192.168.50.31"                 # default: auto-detected route to the backend
    # data_dir = "/var/lib/trapsig-sensor"
    # [[extra_logs]]                               # optional, e.g. Cowrie on the Pi
    # path = "/var/lib/docker/volumes/trapsig-sensor_cowrie-logs/_data/cowrie.json"
    # honeypot_type = "ssh_telnet"
    # honeypot_id = "cowrie-01"
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import socket
import sys
import threading
import time
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

AGENT_VERSION = "3.0"
KEYS = ("sensor_id", "backend_url", "api_key", "ingest_url", "ingest_user", "ingest_password", "sensor_ip", "data_dir", "poll_seconds")


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #


def default_data_dir() -> Path:
    if os.name == "nt":
        return Path(os.getenv("PROGRAMDATA", str(Path.home()))) / "trapsig-sensor"
    return Path("/var/lib/trapsig-sensor") if os.geteuid() == 0 else Path.home() / ".trapsig-sensor"


def load_config(path: str | None) -> dict[str, Any]:
    config: dict[str, Any] = {}
    if path:
        with open(path, "rb") as stream:
            config = tomllib.load(stream)
    for key in KEYS:
        value = os.getenv(f"TRAPSIG_{key.upper()}")
        if value:
            config[key] = value
    for required in ("sensor_id", "backend_url"):
        if not config.get(required):
            raise SystemExit(f"missing '{required}' (config file or TRAPSIG_{required.upper()})")
    config["backend_url"] = str(config["backend_url"]).rstrip("/")
    config["data_dir"] = Path(config.get("data_dir") or default_data_dir())
    config["poll_seconds"] = float(config.get("poll_seconds", 30))
    config.setdefault("sensor_ip", detect_ip(config["backend_url"]))
    config.setdefault("extra_logs", [])
    return config


def detect_ip(backend_url: str) -> str:
    """The local address used to reach the backend (no packets are sent)."""
    host = urllib.parse.urlsplit(backend_url).hostname or "8.8.8.8"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((socket.gethostbyname(host), 9))
            return probe.getsockname()[0]
    except OSError:
        return "0.0.0.0"


def _request(config: dict[str, Any], url: str, body: bytes | None = None, headers: dict[str, str] | None = None, timeout: float = 10) -> bytes:
    request = urllib.request.Request(
        url, data=body, headers={"User-Agent": f"trapsig-agent/{AGENT_VERSION}", **(headers or {})}, method="POST" if body is not None else "GET"
    )
    if config.get("api_key") and url.startswith(config["backend_url"]):
        request.add_header("X-API-Key", config["api_key"])
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured lab URLs
        return response.read(4_000_000)


# --------------------------------------------------------------------------- #
# assignment
# --------------------------------------------------------------------------- #


def fetch_assignment(config: dict[str, Any]) -> dict[str, Any] | None:
    cache = config["data_dir"] / "assignment.json"
    try:
        data = json.loads(_request(config, f"{config['backend_url']}/fleet/{config['sensor_id']}/assignment"))
        cache.write_text(json.dumps(data), encoding="utf-8")
        return data
    except Exception as exc:  # backend down: keep running the cached assignment
        print(f"[agent] assignment fetch failed ({type(exc).__name__}: {exc}); using cache", flush=True)
        return json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else None


class PersonaSet:
    """The personas currently running, replaced as a unit when the assignment changes."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.fingerprint: str | None = None
        self.running: list[tuple[Any, list[threading.Thread], threading.Event]] = []

    def apply(self, assignment: dict[str, Any]) -> None:
        if assignment.get("fingerprint") == self.fingerprint:
            return
        from common.heartbeat import start_heartbeat
        from common.persona import parse_persona
        from common.runtime import serve_persona_native, stop_servers

        for _, threads, beat in self.running:
            beat.set()
            stop_servers(threads)
        self.running = []
        logs = self.config["data_dir"] / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        for entry in assignment.get("personas", []):
            if not entry.get("enabled", True):
                continue
            pid = entry["persona_id"]
            definition = (assignment.get("definitions") or {}).get(pid, {}).get("definition")
            if not definition:
                print(f"[agent] {pid}: no definition in assignment; skipped", flush=True)
                continue
            persona = parse_persona(definition)
            host = entry.get("bind_ip") or "0.0.0.0"
            threads, telemetry, failures = serve_persona_native(
                persona, log_path=str(logs / f"{pid}.jsonl"), sensor_ip=entry.get("bind_ip") or self.config["sensor_ip"], host=host
            )
            for service, error in failures.items():
                print(f"[agent] {pid}:{service} NOT LISTENING ({error})", flush=True)
            print(f"[agent] {pid} v{persona.version} on {host}: {len(threads)} service(s) listening", flush=True)
            beat = start_heartbeat(persona, assignment.get("origin") or "fleet", telemetry, threads)
            self.running.append((persona, threads, beat))
        self.fingerprint = assignment.get("fingerprint")


# --------------------------------------------------------------------------- #
# shipping
# --------------------------------------------------------------------------- #


class Shipper(threading.Thread):
    """Tail JSONL logs and POST them to Logstash's HTTP input with persisted offsets."""

    def __init__(self, config: dict[str, Any], stop: threading.Event) -> None:
        super().__init__(name="shipper", daemon=True)
        self.config, self.stop = config, stop
        self.offsets_path = config["data_dir"] / "offsets.json"
        self.offsets: dict[str, int] = json.loads(self.offsets_path.read_text()) if self.offsets_path.exists() else {}

    def sources(self) -> list[tuple[Path, dict[str, str]]]:
        base = {"sensor_id": self.config["sensor_id"], "sensor_ip": self.config["sensor_ip"]}
        out = [(path, base) for path in sorted((self.config["data_dir"] / "logs").glob("*.jsonl"))]
        for extra in self.config.get("extra_logs", []):
            fields = {**base, "honeypot_type": extra.get("honeypot_type", ""), "honeypot_id": extra.get("honeypot_id", "")}
            out.append((Path(extra["path"]), {k: v for k, v in fields.items() if v}))
        return out

    def ship_once(self, batch_limit: int = 500) -> int:
        url = self.config.get("ingest_url")
        if not url:
            return 0
        shipped = 0
        auth = base64.b64encode(f"{self.config.get('ingest_user', 'trapsig')}:{self.config.get('ingest_password', '')}".encode()).decode()
        for path, fields in self.sources():
            if not path.exists():
                continue
            key = str(path)
            size = path.stat().st_size
            offset = self.offsets.get(key, 0)
            if size < offset:  # rotated or truncated
                offset = 0
            if size == offset:
                continue
            with path.open("rb") as stream:
                stream.seek(offset)
                lines, consumed = [], 0
                for raw in stream:
                    if not raw.endswith(b"\n") or len(lines) >= batch_limit:
                        break  # partial last line: wait for the writer
                    consumed += len(raw)
                    text = raw.decode("utf-8", "replace").strip()
                    if text:
                        lines.append(json.dumps({"message": text, "fields": fields}))
            if not lines:
                continue
            body = ("\n".join(lines) + "\n").encode()
            _request(self.config, url, body, {"Content-Type": "application/x-ndjson", "Authorization": f"Basic {auth}"})
            self.offsets[key] = offset + consumed
            self.offsets_path.write_text(json.dumps(self.offsets))
            shipped += len(lines)
        return shipped

    def run(self) -> None:
        backoff = 1.0
        while not self.stop.is_set():
            try:
                shipped = self.ship_once()
                backoff = 1.0
                self.stop.wait(0.5 if shipped else 2.0)
            except Exception as exc:
                print(f"[agent] shipping failed ({type(exc).__name__}: {exc}); retrying in {backoff:.0f}s", flush=True)
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 60.0)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def prepare_environment(config: dict[str, Any]) -> None:
    config["data_dir"].mkdir(parents=True, exist_ok=True)
    os.environ.update(
        {
            "SENSOR_ID": config["sensor_id"],
            "SENSOR_IP": config["sensor_ip"],
            "BACKEND_URL": config["backend_url"],
            "SENSOR_API_KEY": config.get("api_key", ""),
            "HONEYPOT_HOSTNAME": platform.node() or config["sensor_id"],
            # A self-probe from a bound IP would look like an attacker's sweep.
            "HEARTBEAT_TCP_PROBE": "0",
        }
    )


def run(config: dict[str, Any]) -> None:
    prepare_environment(config)
    from common.hardening import start_posture_poller

    start_posture_poller()
    stop = threading.Event()
    Shipper(config, stop).start()
    personas = PersonaSet(config)
    print(
        f"[agent] {config['sensor_id']} ({platform.system()} {platform.release()}) sensor_ip={config['sensor_ip']} backend={config['backend_url']}", flush=True
    )
    while True:
        assignment = fetch_assignment(config)
        if assignment:
            personas.apply(assignment)
        elif not personas.running:
            print("[agent] no assignment yet (backend unreachable and no cache); retrying", flush=True)
        time.sleep(config["poll_seconds"])


def check(config: dict[str, Any]) -> None:
    prepare_environment(config)
    from common.persona import parse_persona
    from common.plugin import REGISTRY

    assignment = fetch_assignment(config)
    if not assignment:
        raise SystemExit("no assignment available")
    print(f"sensor {assignment['sensor_id']} ({assignment.get('label')}), assignment v{assignment.get('assignment_version')} [{assignment.get('fingerprint')}]")
    blocked = 0
    for entry in assignment["personas"]:
        persona = parse_persona(assignment["definitions"][entry["persona_id"]]["definition"])
        host = entry.get("bind_ip") or "0.0.0.0"
        ports = []
        for service in persona.services:
            transport = REGISTRY[service.plugin].transport
            problem = port_problem(host, service.public_port, transport) if entry.get("enabled", True) else None
            blocked += problem is not None
            ports.append(f"{service.public_port}/{transport}" + (f" [{problem}]" if problem else ""))
        print(f"  {'on ' if entry.get('enabled', True) else 'off'} {persona.id:<22} {host:<16} {', '.join(ports)}")
    print(f"ingest: {config.get('ingest_url') or 'NOT CONFIGURED (events stay local)'}")
    if blocked:
        print(f"{blocked} port(s) cannot be opened (stop the agent first if it is already running; otherwise free the port, "
              "move the persona to another device, or give it a bind_ip)")


def port_problem(host: str, port: int, transport: str) -> str | None:
    """Try to bind ``port`` briefly; return why it cannot be used, or None."""
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as probe:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)  # see sharing as "in use" on Windows
        try:
            probe.bind((host, port))
        except PermissionError:
            return "needs CAP_NET_BIND_SERVICE (install the service) or root"
        except OSError as exc:
            return "in use" if getattr(exc, "errno", None) in (98, 48, 10048, 10013) else f"cannot bind: {exc.strerror or exc}"
    return None


def install(config_path: str, apply: bool) -> None:
    agent = Path(__file__).resolve()
    config = Path(config_path).resolve()
    if os.name == "nt":
        task = f'\\"{sys.executable}\\" \\"{agent}\\" run --config \\"{config}\\"'
        command = f'schtasks /Create /TN "TRAPSIG Sensor" /SC ONSTART /RU "NT AUTHORITY\\LocalService" /RL LIMITED /F /TR "{task}"'
        print(command)
        if apply:
            os.system(command)  # noqa: S605 - operator-requested install of a fixed command
            os.system('schtasks /Run /TN "TRAPSIG Sensor"')  # noqa: S605
        else:
            print("\nRun this in an elevated prompt (or re-run with --apply as Administrator).")
        return
    unit = f"""[Unit]
Description=TRAPSIG sensor agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={sys.executable} {agent} run --config {config}
User=trapsig
Restart=always
RestartSec=5
# Bind privileged decoy ports (21, 23, 80, 102, 161, 502...) without root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=trapsig-sensor
Environment=TRAPSIG_DATA_DIR=/var/lib/trapsig-sensor
MemoryMax=256M
TasksMax=256

[Install]
WantedBy=multi-user.target
"""
    target = Path("/etc/systemd/system/trapsig-sensor.service")
    if apply:
        target.write_text(unit)
        os.system("id trapsig >/dev/null 2>&1 || useradd --system --no-create-home trapsig")  # noqa: S605
        os.system("systemctl daemon-reload && systemctl enable --now trapsig-sensor")  # noqa: S605
        print(f"installed {target}")
    else:
        print(unit)
        print(f"# Save as {target}, then: sudo useradd --system --no-create-home trapsig; sudo systemctl enable --now trapsig-sensor")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("run", "check", "install"))
    parser.add_argument("--config", help="trapsig-sensor.toml (keys can also come from TRAPSIG_* environment variables)")
    parser.add_argument("--apply", action="store_true", help="install: actually write/register the service (needs root / Administrator)")
    args = parser.parse_args()
    if args.command == "install":
        if not args.config:
            parser.error("install needs --config")
        install(args.config, args.apply)
        return
    config = load_config(args.config)
    (check if args.command == "check" else run)(config)


if __name__ == "__main__":
    main()
