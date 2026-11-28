"""Regenerate docs/reference/SCENARIOS.md from attacks/scenarios/*.yaml.

    python scripts/dev/scenario_catalog.py          # rewrite the doc
    python scripts/dev/scenario_catalog.py --check  # exit 1 if the doc is stale (CI)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs/reference/SCENARIOS.md"

HEADER = """# Attack scenarios

{count} bounded, single-target scenarios in `attacks/scenarios/` ({attacks} attacks, {controls} controls,
covering {services} services). Run one with

```bash
python -m attacks.runner.run <id> --target <sensor-ip>                 # LAB_SUBNET must contain the target
python -m attacks.runner.run <id> --target <ip> --experiment-id EXP-... --api-url http://<analysis>:8000
```

The runner validates the target against `LAB_SUBNET`, talks to exactly one host,
caps each step at 64 requests and each pause at 120 s, and never scans, persists
or transfers real payloads (dropper URLs use the unroutable TEST-NET-2 range; TFTP
and FTP transfers are refused by the decoys; Redis writes are acknowledged and
discarded).

**Tested end to end.** `tests/safety/test_scenarios_against_personas.py` executes
every scenario that targets persona services through the real runner against
the real persona runtime, normalizer and detector: each attack must produce its
`expected_detection` and each control must produce no detection. Scenarios that
need the Cowrie container (`ssh`, `telnet`) or the legacy device containers are
exercised in the lab only. `evaluation/measure_hardening.py` runs every in-process
attack under each RL hardening action to measure what the action changes.

Services: `iot-telnet` is the BusyBox telnet shell of embedded personas (DVR);
`telnet` is Cowrie's. ICS: `modbus`, `s7`, `bacnet`, `enip`, `atg` (tank gauge),
`coap`. IT: `snmp`, `redis`, `sip`, `tftp`, `vnc`, `rdp`, `rtsp`, `ftp`, `dns`,
`ssdp`, `web`.

Step options (beyond `service`): `port`, `paths` (HTTP enumeration),
`credentials` + `attempt_interval` (SSH / telnet credential lists), `commands`
(shell lines; Redis argument lists; ATG command codes), `operation`/`topic`/`message`
(MQTT), `requests`/`sweep` (Modbus, CoAP, SNMP), `operations` (S7, EtherNet/IP),
`services` (BACnet), `community`/`communities` (SNMP), `method`/`extensions`/`user_agent`
(SIP), `operation`/`files` (TFTP), `attempts` (VNC), `usernames` (RDP),
`method`/`paths`/`username`/`password` (RTSP), `queries` (DNS),
`search_targets` (SSDP), `pause_before` (low-and-slow pacing).

| Scenario | Kind | Expected detection | Services | Models (ATT&CK) | What it does |
| --- | --- | --- | --- | --- | --- |
"""


def render() -> str:
    docs = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "attacks/scenarios").glob("*.yaml"))]
    docs.sort(key=lambda d: (d["trial_kind"] != "attack", d["id"]))
    services = {s for d in docs for s in d["target_services"]}
    out = HEADER.format(
        count=len(docs),
        attacks=sum(d["trial_kind"] == "attack" for d in docs),
        controls=sum(d["trial_kind"] == "control" for d in docs),
        services=len(services),
    )
    for d in docs:
        description = " ".join(str(d.get("description") or d.get("name")).split()).replace("|", "\\|")
        models = d.get("models") or "—"
        detection = d.get("expected_detection") or "—"
        out += f"| `{d['id']}` | {d['trial_kind']} | {detection} | {', '.join(d['target_services'])} | {models} | {description} |\n"
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = render()
    if args.check:
        current = DOC.read_text(encoding="utf-8") if DOC.exists() else ""
        if current != text:
            sys.exit("docs/reference/SCENARIOS.md is stale: run python scripts/dev/scenario_catalog.py")
        return
    DOC.write_text(text, encoding="utf-8")
    print(f"wrote {DOC}")


if __name__ == "__main__":
    main()
