"""Tooling for running experiments without a Pi: run_matrix options, local lab safety."""

import sys
from argparse import Namespace
from pathlib import Path

import pytest

from evaluation.run_matrix import make_plan, parser

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))


def test_run_matrix_accepts_condition_gap_and_exclusions():
    args = parser().parse_args(
        [
            "--api-url",
            "http://x",
            "--attacker-ip",
            "192.168.50.20",
            "--target-ip",
            "192.168.50.10",
            "--all-controls",
            "--exclude",
            "ftp-control",
            "--condition",
            "baseline",
            "--gap-seconds",
            "25",
            "--repetitions",
            "1",
        ]
    )
    plan = make_plan(args)
    assert args.condition == "baseline" and args.gap_seconds == 25
    assert plan and all(entry["trial_kind"] == "control" for entry in plan)
    assert "ftp-control" not in {entry["scenario_id"] for entry in plan}


def test_heartbeat_tcp_probe_can_be_disabled(monkeypatch):
    from common import heartbeat
    from common.persona import parse_persona

    persona = parse_persona({"id": "hb", "name": "H", "device_type": "generic", "services": [{"plugin": "ftp", "port": 2999}]})
    probed = []
    monkeypatch.setattr(heartbeat, "tcp_listening", lambda port, timeout=0.5: probed.append(port) or True)

    class Alive:
        name = "hb:ftp"

        def is_alive(self):
            return True

    payload = heartbeat.build_payload(persona, "file", None, [Alive()], 0.0, probe=False)
    assert probed == [] and payload["services"][0]["listening"] is True


def test_local_lab_refuses_loopback_or_public_sensor_ip(tmp_path):
    sys.path.insert(0, str(Path("scripts/lab").resolve()))
    import local_lab

    for name in ("elasticsearch-8.19.0", "logstash-8.19.0", "filebeat-8.19.0-windows-x86_64"):
        (tmp_path / name).mkdir()
    for bad in ("127.0.0.1", "8.8.8.8"):
        with pytest.raises(SystemExit, match="private, non-loopback"):
            local_lab.up(Namespace(elastic_home=str(tmp_path), sensor_ip=bad))


def test_local_lab_rewrites_only_the_elasticsearch_host_in_pipelines(tmp_path):
    sys.path.insert(0, str(Path("scripts/lab").resolve()))
    import local_lab

    home = tmp_path / "logstash"
    (home / "config").mkdir(parents=True)
    for name in ("jvm.options", "log4j2.properties"):
        (home / "config" / name).write_text("x")
    settings = local_lab.configure_logstash(home, tmp_path / "run")
    pipelines = sorted((tmp_path / "run" / "logstash-pipeline").glob("*.conf"))
    originals = sorted(Path("elk/logstash/pipelines").glob("*.conf"))
    assert [p.name for p in pipelines] == [p.name for p in originals]
    for local, original in zip(pipelines, originals, strict=True):
        assert local.read_text() == original.read_text().replace("http://elasticsearch:9200", "http://127.0.0.1:9200")
    assert "path.config" in (settings / "pipelines.yml").read_text()
