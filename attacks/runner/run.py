import argparse
import base64
import http.cookiejar
import json
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

import paramiko
import yaml

from backend.app.services.scenario_contract import allowed_step_statuses

from . import ot_it, protocols
from .protocols import ExpectedRejection
from .safety import validate_target

# Default ports match sensor/docker-compose.yml; a step may override with `port`.
PORTS = {
    "ssh": 2222,
    "telnet": 2223,
    "camera": 8081,
    "http": 8081,
    "iot": 9000,
    "mqtt": 1883,
    "router": 8080,
    "web": 8090,
    "modbus": 502,
    "coap": 5683,
    "rtsp": 554,
    "ftp": 21,
    "ssdp": 1900,
    "dns": 53,
    **ot_it.PORTS,
}
MAX_PAUSE_SECONDS = 120  # per step; keeps low-and-slow scenarios bounded
MAX_ATTEMPTS = 64


def port_for(step: dict) -> int:
    port = int(step.get("port", PORTS[step["service"]]))
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return port


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"


def ssh_campaign(target: str, step: dict) -> None:
    """Try a bounded credential list in order; run commands after the first success."""
    credentials = step.get("credentials") or [[step["username"], step["password"]]]
    if len(credentials) > MAX_ATTEMPTS:
        raise ValueError(f"at most {MAX_ATTEMPTS} credential attempts per step")
    for index, (username, password) in enumerate(credentials):
        last = index == len(credentials) - 1
        attempt = {**step, "username": username, "password": password}
        try:
            ssh_login(target, attempt)
            return
        except ExpectedRejection:
            if last:
                raise
        pause = float(step.get("attempt_interval", 0))
        if pause:
            time.sleep(min(pause, MAX_PAUSE_SECONDS / max(1, len(credentials))))


def ssh_login(target: str, step: dict) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(
                target,
                port=port_for({"service": "ssh", **step}),
                username=step["username"],
                password=step["password"],
                timeout=3,
                auth_timeout=3,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.AuthenticationException as exc:
            raise ExpectedRejection(str(exc)) from exc
        commands = step.get("commands") or ([step["command"]] if step.get("command") else [])
        if commands:
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise paramiko.SSHException("SSH transport closed before command execution")
            channel = transport.open_session(timeout=3)
            try:
                # Cowrie models an interactive shell and may close an exec
                # channel before Paramiko receives the exec-request reply.
                # Use the complete shell lifecycle instead of treating that
                # protocol race as a failed command.
                channel.settimeout(3)
                channel.get_pty()
                channel.invoke_shell()
                channel.sendall(("\n".join(commands) + "\nexit\n").encode())
                channel.shutdown_write()
                while not channel.closed and channel.recv(512):
                    pass
            finally:
                channel.close()
    finally:
        client.close()


def http_requests(target: str, service: str, step: dict) -> None:
    """One request, or a bounded path list (enumeration); rejected only if all were 401/403/404."""
    paths = step.get("paths")
    if not paths:
        http_request(target, service, step)
        return
    if len(paths) > MAX_ATTEMPTS:
        raise ValueError(f"at most {MAX_ATTEMPTS} paths per step")
    refused = 0
    for path in paths:
        try:
            http_request(target, service, {**step, "path": path})
        except ExpectedRejection:
            refused += 1
    if refused == len(paths):
        raise ExpectedRejection("every path was refused")


def http_request(target: str, service: str, step: dict) -> None:
    headers = {"User-Agent": step.get("user_agent", USER_AGENT)}
    data = None
    if step.get("auth_mode") == "form":
        data = urlencode({"username": step["username"], "password": step["password"]}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif step.get("username") is not None:
        token = base64.b64encode(f"{step['username']}:{step['password']}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    port = port_for({"service": service, **step})
    request = Request(f"http://{target}:{port}{step.get('path', '/')}", data=data, headers=headers)
    try:
        if data is None:
            urlopen(request, timeout=3).read(512)
        else:
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            opener.open(request, timeout=3).read(512)
    except Exception as exc:
        if getattr(exc, "code", None) in {401, 403, 404}:
            raise ExpectedRejection(f"HTTP {exc.code}") from exc
        raise


def _mqtt_remaining_length(length: int) -> bytes:
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        encoded.append(digit | (0x80 if length else 0))
        if not length:
            return bytes(encoded)


def _mqtt_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(2, "big") + encoded


def mqtt_packet(step: dict) -> bytes:
    operation = step.get("operation", "connect")
    if operation == "connect":
        body = b"\x00\x04MQTT\x04\x02\x00\x0a" + _mqtt_string(step.get("client_id", "mqtt-client"))
        return b"\x10" + _mqtt_remaining_length(len(body)) + body
    if operation == "subscribe":
        body = b"\x00\x01" + _mqtt_string(step.get("topic", "#")) + b"\x00"
        return b"\x82" + _mqtt_remaining_length(len(body)) + body
    if operation == "publish":
        body = _mqtt_string(step.get("topic", "devices/test/set")) + str(step.get("message", "1")).encode()[:256]
        return b"\x30" + _mqtt_remaining_length(len(body)) + body
    if operation == "ping":
        return b"\xc0\x00"
    raise ValueError(f"unsupported MQTT operation: {operation}")


def mqtt_request(target: str, step: dict) -> None:
    with socket.create_connection((target, port_for({"service": "mqtt", **step})), timeout=3) as connection:
        connection.sendall(mqtt_packet(step))
        if step.get("operation") != "publish":  # QoS 0 publish has no acknowledgement
            connection.recv(512)


def raw_request(target: str, service: str, step: dict) -> None:
    with socket.create_connection((target, port_for({"service": service, **step})), timeout=3) as connection:
        connection.sendall(step.get("payload", "STATUS\\r\\n").encode().decode("unicode_escape").encode())
        connection.recv(512)


PROTOCOL_EXECUTORS = {
    "modbus": protocols.modbus,
    "coap": protocols.coap,
    "rtsp": protocols.rtsp,
    "ftp": protocols.ftp,
    "ssdp": protocols.ssdp,
    "dns": protocols.dns,
    **ot_it.EXECUTORS,
}


def execute(target: str, step: dict) -> None:
    service = step["service"]
    pause = float(step.get("pause_before", 0))
    if pause:
        time.sleep(min(pause, MAX_PAUSE_SECONDS))
    if service == "ssh":
        ssh_campaign(target, step)
    elif service in {"camera", "http", "router", "web"}:
        http_requests(target, service, step)
    elif service == "mqtt":
        mqtt_request(target, step)
    elif service in PROTOCOL_EXECUTORS:
        PROTOCOL_EXECUTORS[service](target, port_for(step), step)
    else:
        raw_request(target, service, step)


def run(scenario_id: str, target: str, source: str = "controlled-attacker", experiment_id: str | None = None, api_url: str | None = None) -> dict:
    target = validate_target(target, os.environ.get("LAB_SUBNET", ""))
    path = Path(__file__).parents[1] / "scenarios" / f"{scenario_id}.yaml"
    if not path.exists() or path.stem != scenario_id:
        raise ValueError("unknown scenario")
    raw = path.read_bytes()
    scenario = yaml.safe_load(raw)
    if scenario.get("id") != scenario_id:
        raise ValueError("scenario id does not match its filename")
    started = datetime.now(timezone.utc)
    steps = []
    for number, step in enumerate(scenario["steps"], 1):
        step_started = datetime.now(timezone.utc)
        status, detail = "completed", None
        try:
            execute(target, step)
        except ExpectedRejection as exc:
            status = "rejected" if "rejected" in allowed_step_statuses(step) else "failed"
            detail = str(exc)
        except Exception as exc:
            status, detail = "failed", str(exc)
        item = {
            "step": number,
            "service": step["service"],
            "started_at": step_started.isoformat(),
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
        }
        if detail:
            item["detail"] = detail
        steps.append(item)
    failures = sum(step["status"] == "failed" for step in steps)
    overall = "completed" if failures == 0 else ("failed" if failures == len(steps) else "partial")
    summary = {
        "run_id": "RUN-" + uuid.uuid4().hex[:12],
        "experiment_id": experiment_id,
        "scenario_id": scenario_id,
        "scenario_manifest_sha256": sha256(raw).hexdigest(),
        "target": target,
        "source": source,
        "expected_detection": scenario["expected_detection"],
        "start_time": started.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "steps": steps,
    }
    output = Path(__file__).parents[1] / "runs"
    output.mkdir(exist_ok=True)
    result_path = output / f"{summary['run_id']}.json"
    result_path.write_text(json.dumps(summary, indent=2))
    if experiment_id and api_url:
        request = Request(
            f"{api_url.rstrip('/')}/experiments/{experiment_id}/ground-truth",
            data=json.dumps(summary).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(request, timeout=10).read()
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one bounded TRAPSIG lab scenario")
    parser.add_argument("scenario")
    parser.add_argument("--target", required=True)
    parser.add_argument("--source", default="controlled-attacker")
    parser.add_argument("--experiment-id")
    parser.add_argument("--api-url")
    args = parser.parse_args()
    if bool(args.experiment_id) != bool(args.api_url):
        parser.error("--experiment-id and --api-url must be supplied together")
    print(json.dumps(run(args.scenario, args.target, args.source, args.experiment_id, args.api_url), indent=2))


if __name__ == "__main__":
    main()
