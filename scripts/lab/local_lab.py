"""Run the whole TRAPSIG pipeline on one machine, without a Raspberry Pi or Docker.

    python scripts/lab/local_lab.py up --elastic-home ../local-stack --sensor-ip 172.23.64.1
    python scripts/lab/local_lab.py status --elastic-home ../local-stack
    python scripts/lab/local_lab.py down --elastic-home ../local-stack

What runs (each a background process, logs and PIDs in <elastic-home>/run/):

* Elasticsearch, Logstash and Filebeat from Elastic's official archives
  (8.19.0, the versions pinned in docker-compose.yml), configured from the repo's
  own templates and pipelines, bound to 127.0.0.1;
* a **virtual Pi**: all six persona honeypots in one process, on their *public*
  ports (502, 21, 554, ...), bound to ``--sensor-ip``;
* the FastAPI backend (127.0.0.1:8000) and the built Next.js console (127.0.0.1:3000).

``--sensor-ip`` must be a private, non-loopback address that is **not reachable
from your LAN** (loopback traffic is deliberately excluded from analysis). On
Windows with WSL the Hyper-V adapter (``vEthernet (WSL)``, e.g. 172.23.64.1) is
ideal. Cowrie (SSH/Telnet) is not available outside Docker, so the two SSH
scenarios are skipped in this mode.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERSION = "8.19.0"
WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _homes(root: Path) -> dict[str, Path]:
    suffix = "-windows-x86_64" if WINDOWS else "-linux-x86_64"
    return {
        "elasticsearch": root / f"elasticsearch-{VERSION}",
        "logstash": root / f"logstash-{VERSION}",
        "filebeat": next(iter(sorted(root.glob(f"filebeat-{VERSION}*"))), root / f"filebeat-{VERSION}{suffix}"),
    }


def _http(method: str, url: str, body: bytes | None = None, timeout: float = 10) -> tuple[int, str]:
    request = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def _wait(url: str, seconds: int, name: str) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if _http("GET", url, timeout=3)[0] < 500:
                print(f"  {name} is up")
                return
        except OSError:
            pass
        time.sleep(2)
    raise SystemExit(f"{name} did not become ready at {url} within {seconds}s (see run/*.log)")


def _spawn(run: Path, name: str, command: list[str], env: dict[str, str] | None = None, cwd: Path | None = None) -> None:
    log = open(run / f"{name}.log", "ab")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0
    process = subprocess.Popen(
        command, stdout=log, stderr=subprocess.STDOUT, env={**os.environ, **(env or {})}, cwd=cwd, creationflags=flags, start_new_session=not WINDOWS
    )
    pids = _pids(run)
    pids[name] = process.pid
    (run / "pids.json").write_text(json.dumps(pids, indent=2))
    print(f"  started {name} (pid {process.pid})")


def _pids(run: Path) -> dict[str, int]:
    path = run / "pids.json"
    return json.loads(path.read_text()) if path.exists() else {}


def _alive(pid: int) -> bool:
    if WINDOWS:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #


def configure_elasticsearch(home: Path, run: Path) -> None:
    (home / "config" / "elasticsearch.yml").write_text(
        "cluster.name: trapsig\n"
        "node.name: trapsig-local\n"
        "network.host: 127.0.0.1\n"
        "http.port: 9200\n"
        "discovery.type: single-node\n"
        "xpack.security.enabled: false\n"
        "ingest.geoip.downloader.enabled: false\n"
        f"path.data: {(run / 'es-data').as_posix()}\n"
        f"path.logs: {(run / 'es-logs').as_posix()}\n"
    )


def install_templates(base: str = "http://127.0.0.1:9200") -> None:
    """Python port of elk/elasticsearch/setup/install-templates.sh."""
    elk = REPO / "elk" / "elasticsearch"
    for path in sorted((elk / "ilm").glob("*.json")):
        _check(_http("PUT", f"{base}/_ilm/policy/{path.stem}", path.read_bytes()), path.name)
    for path in sorted((elk / "index-templates").glob("*.json")):
        _check(_http("PUT", f"{base}/_index_template/{path.stem}", path.read_bytes()), path.name)
    for path in sorted((elk / "mapping-upgrades").glob("*.json")):
        if _http("HEAD", f"{base}/{path.stem}")[0] == 200:
            _check(_http("PUT", f"{base}/{path.stem}/_mapping", path.read_bytes()), path.name)
    print("  templates, ILM and mapping upgrades installed")


def _check(result: tuple[int, str], what: str) -> None:
    if result[0] >= 300:
        raise SystemExit(f"Elasticsearch rejected {what}: {result[1][:400]}")


def configure_logstash(home: Path, run: Path) -> Path:
    settings, pipeline = run / "logstash-settings", run / "logstash-pipeline"
    for directory in (settings, pipeline):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
    for name in ("jvm.options", "log4j2.properties"):
        shutil.copy(home / "config" / name, settings / name)
    for conf in sorted((REPO / "elk" / "logstash" / "pipelines").glob("*.conf")):
        (pipeline / conf.name).write_text(conf.read_text(encoding="utf-8").replace("http://elasticsearch:9200", "http://127.0.0.1:9200"), encoding="utf-8")
    (settings / "logstash.yml").write_text(
        "pipeline.ecs_compatibility: v8\napi.http.host: 127.0.0.1\n"
        f"path.data: {(run / 'logstash-data').as_posix()}\npath.logs: {(run / 'logstash-logs').as_posix()}\n"
    )
    (settings / "pipelines.yml").write_text(f'- pipeline.id: trapsig\n  path.config: "{pipeline.as_posix()}/*.conf"\n')
    return settings


def configure_filebeat(run: Path, sensor_ip: str) -> Path:
    config = run / "filebeat.yml"
    logs = (run / "sensor-logs").as_posix()
    config.write_text(
        "filebeat.inputs:\n"
        "  - type: filestream\n"
        "    id: custom-honeypots\n"
        f'    paths: ["{logs}/*.jsonl"]\n'
        f'    fields: {{sensor_id: local-sensor, sensor_ip: "{sensor_ip}"}}\n'
        "processors:\n"
        "  - add_fields: {target: observer, fields: {name: trapsig-local, type: honeypot_sensor}}\n"
        "output.logstash:\n"
        '  hosts: ["127.0.0.1:5044"]\n'
        "logging.level: warning\n"
    )
    return config


# --------------------------------------------------------------------------- #
# virtual Pi: every persona on its public ports
# --------------------------------------------------------------------------- #


def run_personas(sensor_ip: str, log_dir: Path) -> None:
    sys.path.insert(0, str(REPO / "sensor" / "honeypots"))
    from common.hardening import start_posture_poller
    from common.heartbeat import start_heartbeat
    from common.persona import load_directory
    from common.runtime import serve_persona

    os.environ.setdefault("SENSOR_ID", "local-sensor")
    os.environ.setdefault("HONEYPOT_HOSTNAME", "trapsig-local")
    os.environ["SENSOR_IP"] = sensor_ip
    # Probing our own ports from the sensor IP would look like an attacker's
    # multi-service sweep (that IP is also the attacker here); use thread liveness.
    os.environ["HEARTBEAT_TCP_PROBE"] = "0"
    start_posture_poller()
    log_dir.mkdir(parents=True, exist_ok=True)
    for persona in load_directory(REPO / "sensor" / "honeypots" / "personas").values():
        served = []
        for service in list(persona.services):
            service.port = service.public_port  # no Docker port mapping: listen where attackers connect
        for service in list(persona.services):
            single = [service]
            persona.services, original = single, persona.services
            try:
                threads, telemetry = serve_persona(persona, log_path=str(log_dir / f"{persona.id}.jsonl"), sensor_ip=sensor_ip, host=sensor_ip)
                served.append((service, threads, telemetry))
                print(f"  {persona.id}:{service.name} listening on {sensor_ip}:{service.port}", flush=True)
            except OSError as exc:
                print(f"  {persona.id}:{service.name} SKIPPED (port {service.port} unavailable: {exc})", flush=True)
            finally:
                persona.services = original
        active = [s for s, _, _ in served]
        persona.services = active
        if served:
            start_heartbeat(persona, "file", served[0][2], [t for _, ts, _ in served for t in ts])
    threading.Event().wait()


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def start_backend(run: Path, subnet: str) -> None:
    revision = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=REPO).stdout.strip() or "local"
    backend_env = {
        "ELASTICSEARCH_URL": "http://127.0.0.1:9200",
        "LAB_SUBNET": subnet,
        "PROCESSING_INTERVAL_SECONDS": "10",
        "KIBANA_URL": "",
        "PYTHONUNBUFFERED": "1",
        "TRAPSIG_REVISION": revision,  # lets runs form a scored evaluation cohort
        # One attacker IP runs every scenario here, so keep sessions short and
        # pause longer than this between runs (run_matrix --gap-seconds).
        "SESSION_TIMEOUT_SECONDS": os.getenv("SESSION_TIMEOUT_SECONDS", "20"),
        "HARDENING_MODE": os.getenv("HARDENING_MODE", "enforce"),
    }
    _spawn(run, "backend", [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000"], backend_env, cwd=REPO)
    _wait("http://127.0.0.1:8000/health/live", 60, "Backend API")


def up(args: argparse.Namespace) -> None:
    root = Path(args.elastic_home).resolve()
    run = root / "run"
    run.mkdir(parents=True, exist_ok=True)
    homes = _homes(root)
    for name, home in homes.items():
        if not home.exists():
            raise SystemExit(f"{name} not found at {home}; extract the {VERSION} archive into {root}")
    address = ipaddress.ip_address(args.sensor_ip)
    if address.is_loopback or not address.is_private:
        raise SystemExit("--sensor-ip must be a private, non-loopback address (loopback traffic is excluded from analysis)")
    subnet = str(ipaddress.ip_network(f"{args.sensor_ip}/24", strict=False))
    exe = ".bat" if WINDOWS else ""

    print("Elasticsearch")
    configure_elasticsearch(homes["elasticsearch"], run)
    _spawn(run, "elasticsearch", [str(homes["elasticsearch"] / "bin" / f"elasticsearch{exe}")], {"ES_JAVA_OPTS": "-Xms1g -Xmx1g"})
    _wait("http://127.0.0.1:9200/_cluster/health", 180, "Elasticsearch")
    install_templates()

    print("Logstash")
    settings = configure_logstash(homes["logstash"], run)
    _spawn(run, "logstash", [str(homes["logstash"] / "bin" / f"logstash{exe}"), "--path.settings", str(settings)], {"LS_JAVA_OPTS": "-Xms512m -Xmx512m"})
    _wait("http://127.0.0.1:9600/_node/pipelines", 240, "Logstash")

    print("Virtual Pi (personas)")
    sensor_env = {"BACKEND_URL": "http://127.0.0.1:8000", "PYTHONUNBUFFERED": "1"}
    _spawn(
        run,
        "personas",
        [sys.executable, str(Path(__file__).resolve()), "personas", "--sensor-ip", args.sensor_ip, "--log-dir", str(run / "sensor-logs")],
        sensor_env,
    )
    time.sleep(3)

    print("Filebeat")
    config = configure_filebeat(run, args.sensor_ip)
    filebeat = homes["filebeat"] / ("filebeat.exe" if WINDOWS else "filebeat")
    _spawn(run, "filebeat", [str(filebeat), "-e", "-c", str(config), "--path.data", str(run / "filebeat-data"), "--strict.perms=false"], cwd=homes["filebeat"])

    print("Backend API")
    start_backend(run, subnet)

    print("Console")
    frontend = REPO / "frontend"
    if not (frontend / ".next").exists():
        subprocess.run("npm run build", shell=True, cwd=frontend, check=True)
    npx = "npx.cmd" if WINDOWS else "npx"
    _spawn(run, "frontend", [npx, "next", "start", "-H", "127.0.0.1", "-p", "3000"], {"API_URL": "http://127.0.0.1:8000"}, cwd=frontend)
    _wait("http://127.0.0.1:3000/live", 90, "Console")

    print(f"\nTRAPSIG is running.\n  Console  http://127.0.0.1:3000\n  API      http://127.0.0.1:8000/docs\n  Sensor   {args.sensor_ip} (LAB_SUBNET={subnet})")
    print(f"Attack it:\n  set LAB_SUBNET={subnet}\n  python -m attacks.runner.run ics-setpoint-tamper --target {args.sensor_ip}")


def restart_backend(args: argparse.Namespace) -> None:
    """Restart only the API (e.g. to switch HARDENING_MODE between experiment arms)."""
    run = Path(args.elastic_home).resolve() / "run"
    pid = _pids(run).get("backend")
    if pid:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True) if WINDOWS else os.kill(pid, signal.SIGTERM)
        time.sleep(2)
    start_backend(run, str(ipaddress.ip_network(f"{args.sensor_ip}/24", strict=False)))
    print(f"  HARDENING_MODE={os.getenv('HARDENING_MODE', 'enforce')}")


def restart_personas(args: argparse.Namespace) -> None:
    run = Path(args.elastic_home).resolve() / "run"
    pid = _pids(run).get("personas")
    if pid:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True) if WINDOWS else os.kill(pid, signal.SIGTERM)
        time.sleep(2)
    env = {"BACKEND_URL": "http://127.0.0.1:8000", "PYTHONUNBUFFERED": "1"}
    _spawn(
        run, "personas", [sys.executable, str(Path(__file__).resolve()), "personas", "--sensor-ip", args.sensor_ip, "--log-dir", str(run / "sensor-logs")], env
    )


def down(args: argparse.Namespace) -> None:
    run = Path(args.elastic_home).resolve() / "run"
    for name, pid in reversed(list(_pids(run).items())):
        if WINDOWS:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
        else:
            try:
                os.killpg(pid, signal.SIGTERM)
            except OSError:
                pass
        print(f"  stopped {name}")
    (run / "pids.json").unlink(missing_ok=True)


def status(args: argparse.Namespace) -> None:
    run = Path(args.elastic_home).resolve() / "run"
    for name, pid in _pids(run).items():
        print(f"  {name:<14} pid {pid:<7} {'running' if _alive(pid) else 'STOPPED'}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "down", "status", "restart-backend", "restart-personas"):
        command = sub.add_parser(name)
        command.add_argument("--elastic-home", required=True, help="directory holding the extracted Elastic 8.19.0 archives")
        if name in {"up", "restart-backend", "restart-personas"}:
            command.add_argument("--sensor-ip", required=True, help="private, non-loopback, LAN-unreachable address for the virtual Pi")
    personas = sub.add_parser("personas", help=argparse.SUPPRESS)
    personas.add_argument("--sensor-ip", required=True)
    personas.add_argument("--log-dir", required=True)
    args = parser.parse_args()
    if args.command == "personas":
        run_personas(args.sensor_ip, Path(args.log_dir))
    else:
        {"up": up, "down": down, "status": status, "restart-backend": restart_backend, "restart-personas": restart_personas}[args.command](args)


if __name__ == "__main__":
    main()
