# TRAPSIG

[![TRAPSIG CI](https://github.com/namelessweakl1ng/IOT-honeypot-IDS/actions/workflows/ci.yml/badge.svg)](https://github.com/namelessweakl1ng/IOT-honeypot-IDS/actions/workflows/ci.yml)

TRAPSIG is an IoT/OT honeypot and cybersecurity **research** platform. A fleet of
sensor devices (a Raspberry Pi plus Linux or Windows hosts, all centrally managed)
runs 16 declarative device personas: PLCs (Modbus and S7), tank gauge, drive,
air handler, building controller, HMI, camera, DVR, router, IIoT gateway, NAS,
printer, VoIP phone, engineering workstation, edge server, plus Cowrie SSH/Telnet.
These run over bounded protocol emulators: HTTP, MQTT, Modbus/TCP, S7comm,
BACnet/IP, EtherNet/IP, tank-gauge, CoAP, RTSP, FTP, telnet, SNMP, Redis, SIP,
TFTP, VNC, RDP, SSDP/UPnP and DNS. Telemetry is
normalized into a versioned schema, reconstructed into attacker sessions, and
classified by three explainable detection engines: Sigma-style rules, a learned
linear policy, and an isolation-forest novelty detector. Each detection carries
its evidence, ATT&CK mapping and per-engine reasoning. Optional passive Zeek
monitoring is joined to honeypot interactions by Community ID. A reinforcement-
learning agent hardens each attacking source (tarpit, refuse logins, read-only,
quarantine) and learns which response works. An experiment laboratory answers
questions such as *"did RL hardening stop attackers without hurting detection?"*
with controlled arms, Fisher exact tests and hash-verified dataset exports.

It is a laboratory instrument for an **isolated private network**, not a
production SIEM and not an Internet-facing honeypot.

## Capabilities at a glance

| Area | What exists | Where |
| --- | --- | --- |
| Device personas | 16 TOML personas (6 OT, 10 IT/IoT) plus Cowrie; versioned edits via API; deployment drift visible | `sensor/honeypots/personas/`, `/personas` |
| Multi-device fleet | One stdlib-only agent for Pi OS Lite, Linux and Windows. It pulls its assignment, hot-reloads personas, ships events over HTTP to Logstash, and installs as a systemd unit or Windows task. Personas are assigned per device (optionally per IP alias) in the console, with port-conflict validation | `sensor/honeypots/agent.py`, `/fleet`, [DEPLOYMENT](docs/guides/DEPLOYMENT.md) |
| Protocols | Plugin registry; Modbus/TCP, S7comm, BACnet/IP, EtherNet/IP+CIP, tank gauge, CoAP, RTSP, FTP (no data channel), telnet (BusyBox), SNMP v1/v2c, Redis, SIP, TFTP (refuses transfers), VNC, RDP, SSDP, authoritative-only DNS, configurable HTTP; legacy camera/router/IoT/MQTT; Cowrie | `sensor/honeypots/plugins/` |
| Sensor safety | Per-connection message/time bounds, per-source connection cap, UDP reflection guard (rate + 10× size cap), read-only containers, no privileged ports | `sensor/honeypots/common/runtime.py` |
| Fleet | Authenticated heartbeats → derived health per sensor and persona instance | `/sensors` |
| Telemetry | Schema v2 (persona, transport, Community ID, connection/sequence, protocol namespaces) with v1 compatibility; dead-letter routing; immutable raw events | `elk/`, [EVENT_SCHEMA](docs/reference/EVENT_SCHEMA.md) |
| Network intelligence | Optional Zeek (`netmon` profile) → `trapsig-network-*`, exact Community-ID correlation, network-only scan detection | `/network`, [ADR-0006](docs/adr/0006-zeek-community-id.md) |
| Detection | 54 Sigma-style rules (with 110 embedded test cases), a learned 13-head calibrated model, isolation forest; hybrid merge with exact evidence, feature contributions, ATT&CK | `backend/app/rules/`, [DETECTION](docs/reference/DETECTION.md) |
| Attack scenarios | 67 bounded scenarios (55 attacks, 12 controls). They include Mirai-style SSH and DVR-telnet infection, S7 PLC stop and logic download, BACnet setpoint override, CIP drive writes, tank-gauge relabel, Redis key implant and rogue master, SNMP abuse, SIPVicious sweeps, TFTP implant, RDP/VNC probing, an IT-to-OT campaign, ICS setpoint tampering and CoAP/MQTT command injection. Closed-loop tested | [SCENARIOS](docs/reference/SCENARIOS.md) |
| Evaluation | Grouped-CV engine comparison (per-class P/R/F1, macro-F1, FPR/FNR, latency, model size, leakage quantification) | `/detection/comparisons`, `backend/app/tools/compare_detectors.py` |
| Experiments | Objective/hypothesis/condition, lifecycle, ground truth, archiving, arm comparison for detection (Wilson CI, Fisher exact) and for defence (attacker success per arm), dataset bundles; orphaned runs are abandoned automatically | `/experiments`, `evaluation/`, Evaluation page |
| Adaptive defence (RL) | A Thompson-sampling agent picks per-source hardening (tarpit, deny_auth, read_only, quarantine) by kill-chain stage × IT/OT surface × history, measures the attacker's next moves, and learns. It uses hierarchical pooling, discounting and a per-source poisoning cap, and is trained offline on outcomes measured against the real personas, with a held-out evaluation and a promotion gate. Every change and reason is on the dashboard | [HARDENING](docs/reference/HARDENING.md), [ADR-0008](docs/adr/0008-rl-hardening-agent.md) |
| Security | Role-based API keys (viewer/analyst/admin/sensor), audit trail of writes and denials | [SECURITY](docs/reference/SECURITY.md) |
| Console | Ten pages: Overview, Live Operations (SSE), Investigate (events + sessions), Detections, Adaptive Defence, Experiments, Evaluation (detection metrics, scenario coverage, RL containment, engine and arm comparisons), Detection Lab (rules, engines, ATT&CK coverage), Sensors & Personas, Observability (pipeline, network, audit); Kibana optional (`--profile kibana`) | `frontend/` |

## Find your way around

| Folder | What lives there | Start with |
| --- | --- | --- |
| [`sensor/`](sensor/) | Everything attackers touch: personas, protocol emulators, the fleet agent | [sensor/README](sensor/README.md) |
| [`backend/`](backend/) | Analysis API: processing, detection, RL hardening, fleet, experiments | [backend/README](backend/README.md) |
| [`frontend/`](frontend/) | The research console (10 pages) | [frontend/README](frontend/README.md) |
| [`elk/`](elk/) | Logstash pipelines and Elasticsearch templates | [elk/README](elk/README.md) |
| [`attacks/`](attacks/) | Controlled attacker: 67 scenarios and the runner | [attacks/README](attacks/README.md) |
| [`evaluation/`](evaluation/) | Experiment batches, arm comparisons, RL measurement | [evaluation/README](evaluation/README.md) |
| [`scripts/`](scripts/) | Helpers by job: `lab/`, `pi/`, `analysis-host/`, `dev/`, `ci/` | [scripts/README](scripts/README.md) |
| [`tests/`](tests/) | 639 tests, incl. the closed attack -> sensor -> detector loop | [tests/README](tests/README.md) |
| [`docs/`](docs/) | Guides, reference, research method, project record | **[docs/README](docs/README.md)** |

Root files: `docker-compose.yml` (analysis stack), `.env.example` (its settings),
`pyproject.toml` (lint, type and test config) and `requirements-dev.txt`.

## Get started

Pick one:

1. **Everything on one PC (no Pi, no Docker).** The quickest way to see it work.
   See [below](#run-everything-on-one-machine-no-pi-no-docker).
2. **Several devices.** A Pi plus Linux/Windows hosts, each running the fleet agent,
   managed from the console: [docs/guides/DEPLOYMENT.md](docs/guides/DEPLOYMENT.md).
3. **One Pi with Docker, plus the analysis PC.** A copy-paste demo guide:
   [docs/guides/CONNECT_AND_DEMO.md](docs/guides/CONNECT_AND_DEMO.md) (details in
   [SETUP](docs/guides/SETUP.md)).

## Architecture

```text
controlled attacker ──► sensor devices (Pi OS Lite / Linux / Windows)
                         ├─ agent.py: the device's assigned personas on their real ports ──HTTP :5045──┐
                         ├─ (Docker mode on a Pi) Cowrie + persona containers + Filebeat ──Beats :5044──┤
                         └─ Zeek passive monitor (--profile netmon, optional)                           │
                                                                                                        ▼
analysis host:  Logstash (normalize, validate, dead-letter) ──► Elasticsearch (the only store)
                                                                     │
                 FastAPI: incremental processor (sessions → rules + ML + anomaly → detections → RL hardening),
                          fleet assignments, experiments, personas, sensors, network, SSE, RBAC/audit
                                                                     │        ▲ agents poll assignments
                 Next.js research console                 Kibana (optional) └─ and hardening postures
```

Raw events are immutable; derived documents use content-derived IDs, so restarts
and replicas converge. No message broker is used; see
[ADR-0001](docs/adr/0001-keep-elasticsearch-no-broker.md) for why. More detail is in
[ARCHITECTURE](docs/reference/ARCHITECTURE.md).

## Run everything on one machine (no Pi, no Docker)

`scripts/lab/local_lab.py` runs the real pipeline natively: Elasticsearch, Logstash
and Filebeat from Elastic's official 8.19.0 archives (the versions pinned in
Compose), configured from this repo's templates and pipelines; a **virtual Pi**
hosting all 16 personas on their public ports; the API; and the console.

1. Download and extract the Windows or Linux `.zip`/`.tar.gz` of Elasticsearch,
   Logstash and Filebeat 8.19.0 from `artifacts.elastic.co` into a folder outside
   the repo (e.g. `../local-stack`), and check them against the published `.sha512`.
2. Choose a sensor address that is **private, not loopback and not reachable from
   your LAN**. Loopback traffic is excluded from analysis by design, and the
   decoys must not be exposed. On Windows with WSL, use the `vEthernet (WSL)`
   address (`Get-NetIPAddress`, e.g. `172.23.64.1`).
3. Build the console once (`cd frontend && npm ci && npm run build`), then:

```bash
python scripts/lab/local_lab.py up --elastic-home ../local-stack --sensor-ip 172.23.64.1
# console http://127.0.0.1:3000 · API http://127.0.0.1:8000/docs
python scripts/lab/local_lab.py status --elastic-home ../local-stack
python scripts/lab/local_lab.py down --elastic-home ../local-stack
```

In this mode:
* Cowrie is not available, so exclude SSH/Telnet-Cowrie scenarios.
* The attacker and sensor share one IP. Sessions are shortened to 20 s, so use
  `--gap-seconds 30` between runs.
* The heartbeat's self-probe is disabled.

## Common tasks

```bash
# one attack (LAB_SUBNET must contain the target)
LAB_SUBNET=172.23.64.0/24 python -m attacks.runner.run s7-plc-stop --target 172.23.64.1

# an experiment batch, then the RL arm, then compare
LAB_SUBNET=172.23.64.0/24 python -m evaluation.run_matrix --api-url http://127.0.0.1:8000 \
  --attacker-ip 172.23.64.1 --target-ip 172.23.64.1 --all-attacks --repetitions 2 --shuffle --seed 1 \
  --gap-seconds 30 --condition baseline --batch-id MY-BASELINE --execute
HARDENING_MODE=enforce python scripts/lab/local_lab.py restart-backend --elastic-home ../local-stack --sensor-ip 172.23.64.1
#   ... same run_matrix with --condition rl-hardening --batch-id MY-RL ...
python -m evaluation.arm_outcomes --api-url http://127.0.0.1:8000 --arm baseline=MY-BASELINE --arm rl-hardening=MY-RL

# learned detector and RL agent
python -m backend.app.tools.train_detector              # gated: only an improved model becomes active
python -m evaluation.measure_hardening                  # measure each RL action on the real personas
python -m backend.app.tools.train_hardening             # train + held-out gate (--apply installs if it passes)
python -m backend.app.tools.compare_detectors --source logged --store

# extras
docker compose --profile netmon up -d zeek              # passive Zeek on the Pi (~150-250 MB RAM)
python scripts/dev/benchmark.py                         # detection/processing performance, no infrastructure
```

Experiments through the API: `POST /experiments`, then `/start`, run the scenario,
then `/finish`. Finishing correlates events by time window, attacker and target,
and records TP/FN/TN/FP/INCONCLUSIVE. Method: [EXPERIMENTS](docs/research/EXPERIMENTS.md).

## Test and validate

```bash
pip install -r backend/requirements.txt -r attacks/requirements.txt -r requirements-dev.txt
(cd frontend && npm ci)
python -m ruff check . && python -m mypy && python -m pytest -q
(cd frontend && npx eslint src && npx tsc --noEmit && npm run build)
./scripts/dev/validate.sh        # bash: also validates both Compose files and shell scripts
```

CI additionally runs coverage, a secret scan (gitleaks), Trivy, an SBOM, image
builds, and Elasticsearch/Logstash/API smoke tests.

## Evidence so far

Measured in the local lab (real Elasticsearch/Logstash/Filebeat, 16 personas, 24
attack runs per arm). With RL hardening, attacker success fell from **67% to
8%** (Fisher p = 5.8 × 10⁻⁵), detection recall stayed at 100%, and there were no
false positives. Read the caveats (single attacker IP, untrained agent) in
[IMPLEMENTATION_LOG §11](docs/project/IMPLEMENTATION_LOG.md). The offline-trained
policy matches but does not significantly beat an expert rule table, so it is not
installed by default; see [HARDENING](docs/reference/HARDENING.md). No measurement
has been made on the physical Pi/Windows fleet yet.

## Safety

Run only on an isolated private lab network you own. Do not expose the decoys to
the Internet. Every emulator is bounded:
* no protocol executes attacker input; shells are emulated, downloads are never
  fetched, and FTP/TFTP never transfer files;
* DNS never recurses, and UDP replies are rate- and size-limited against reflection;
* process writes touch only connection-local state;
* agents run unprivileged (systemd with only `CAP_NET_BIND_SERVICE`, or Windows
  LocalService), and containers run read-only.

The attack runner refuses any target outside `LAB_SUBNET`. Keep keys and `.env`
out of Git. See [SECURITY](docs/reference/SECURITY.md).

Design decisions are in [`docs/adr/`](docs/adr/); the work record is in
[`docs/project/IMPLEMENTATION_LOG.md`](docs/project/IMPLEMENTATION_LOG.md) and the
outstanding work is in [`docs/project/ROADMAP.md`](docs/project/ROADMAP.md).
