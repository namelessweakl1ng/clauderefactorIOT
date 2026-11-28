import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from backend.app.services.pi_manager import HONEYPOTS, MANAGE_SCRIPT

ROOT = Path(__file__).parents[2]


def load_compose(path: str):
    return yaml.safe_load((ROOT / path).read_text())


def test_analysis_deployment_contracts():
    text = (ROOT / "docker-compose.yml").read_text()
    compose = load_compose("docker-compose.yml")
    for mount in (
        "elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro,Z",
        "logstash/config:/usr/share/logstash/config:ro,Z",
        "logstash/pipelines:/usr/share/logstash/pipeline:ro,Z",
        "kibana.yml:/usr/share/kibana/config/kibana.yml:ro,Z",
        "trapsig.ndjson:/assets/trapsig.ndjson:ro,Z",
        "pi_ssh_key}:/run/trapsig-secrets/pi_ssh_key:ro,Z",
        "known_hosts}:/run/trapsig-secrets/known_hosts:ro,Z",
    ):
        assert mount in text
    assert compose["services"]["frontend"]["environment"]["HOSTNAME"] == "0.0.0.0"
    assert "127.0.0.1:3000" in compose["services"]["frontend"]["healthcheck"]["test"][-1]
    kibana = compose["services"]["kibana"]
    assert kibana["environment"]["NODE_OPTIONS"] == "--max-old-space-size=768"
    assert kibana["mem_limit"] == "1536m"


def test_sensor_health_and_permissions_contracts():
    compose = load_compose("sensor/docker-compose.yml")
    services = compose["services"]
    assert services["custom-logs-init"]["command"] == ["chown", "-R", "10001:10001", "/logs"]
    for name in ("camera", "router", "gateway", "plc", "building", "nas"):
        service = services[name]
        assert service["build"]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["depends_on"]["custom-logs-init"]["condition"] == "service_completed_successfully"
        assert service["healthcheck"]["test"] == ["CMD", "python", "/usr/local/bin/healthcheck.py"]
    assert services["cowrie"]["healthcheck"]["test"][0] == "CMD"
    assert services["cowrie"]["healthcheck"]["test"][1] == "/cowrie/cowrie-env/bin/python"
    assert services["filebeat"]["healthcheck"]["test"][0] == "CMD"
    assert "--strict.perms=false" in services["filebeat"]["healthcheck"]["test"]
    assert services["filebeat"]["depends_on"] == {
        "custom-logs-init": {"condition": "service_completed_successfully"}
    }


def test_cowrie_runtime_configuration_is_deterministic():
    compose = load_compose("sensor/docker-compose.yml")
    cowrie = compose["services"]["cowrie"]
    config = (ROOT / "sensor/honeypots/cowrie/cowrie.cfg").read_text()
    userdb = ROOT / "sensor/honeypots/cowrie/userdb.txt"

    assert "logfile = var/log/cowrie/cowrie.json" in config
    assert userdb.read_text().splitlines() == ["root:x:root", "*:x:!*"]
    assert "./honeypots/cowrie/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro" in cowrie["volumes"]


def test_sensor_start_rebuilds_changed_custom_images():
    command = (ROOT / "sensor/scripts/start.sh").read_text()
    assert "docker compose up -d --build" in command
    assert "--no-cache" not in command


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("start", ["compose up -d filebeat cowrie"]),
        ("stop", ["compose stop cowrie"]),
        (
            "restart",
            ["compose up -d filebeat", "compose up -d --force-recreate cowrie"],
        ),
    ],
)
def test_sensor_manager_actions_create_or_control_service(tmp_path, action, expected):
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("no POSIX shell available to exercise the manager")

    docker = tmp_path / "docker"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_LOG"\n')
    docker.chmod(0o755)
    log = tmp_path / "docker.log"
    environment = {"PATH": f"{tmp_path}:/usr/bin:/bin", "DOCKER_LOG": str(log)}

    result = subprocess.run(
        [shell, str(ROOT / "sensor/scripts/manage.sh"), action, "cowrie"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert log.read_text().splitlines() == expected


def test_ssh_wrapper_is_an_exact_whitelist():
    wrapper = ROOT / "sensor/scripts/ssh-manage-wrapper.sh"
    text = wrapper.read_text()
    assert "eval" not in text
    assert "sh -c" not in text
    assert f"MANAGER={MANAGE_SCRIPT}" in text
    assert "${SSH_ORIGINAL_COMMAND:-}" in text
    expected_commands = {f"{MANAGE_SCRIPT} status"}
    for service in ("cowrie", "camera", "router", "gateway", "plc", "building", "nas"):
        for action in ("start", "stop", "restart"):
            expected_commands.add(f"{MANAGE_SCRIPT} {action} {service}")
            assert f'"$MANAGER {action} {service}")' in text
    assert set(HONEYPOTS) == {"cowrie", "camera", "router", "gateway", "plc", "building", "nas"}
    assert '"$MANAGER status")' in text
    accepted = {line.split('")', 1)[0].replace('  "$MANAGER', MANAGE_SCRIPT) for line in text.splitlines() if line.startswith('  "$MANAGER ')}
    assert accepted == expected_commands
    # Invoke through an explicit POSIX shell so the behavioural check runs on
    # both Linux (CI/Pi) and Windows dev machines (Git Bash provides `sh`); the
    # shebang alone is not executable on Windows.
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("no POSIX shell available to exercise the wrapper")
    denied = subprocess.run([shell, str(wrapper)], env={"SSH_ORIGINAL_COMMAND": "uname -a"}, text=True, capture_output=True, check=False)
    assert denied.returncode != 0
    assert "Denied" in denied.stderr


def test_pi_setup_documents_and_checks_docker_access():
    setup = (ROOT / "sensor/scripts/setup.sh").read_text()
    guide = (ROOT / "docs/guides/SETUP.md").read_text()
    assert "id -nG trapsig" in setup
    assert "sudo usermod -aG docker trapsig" in guide
    assert "sudo -u trapsig docker info" in guide
    assert "new login/SSH session" in guide
    assert "highly privileged" in guide
