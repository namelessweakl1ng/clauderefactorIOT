# Security model

TRAPSIG is itself a security system attracting hostile input. These are its
boundaries, with where each one is enforced.

## Isolation and blast radius

| Threat | Control | Enforced in |
| --- | --- | --- |
| Attacker input executes | No emulator executes or evaluates input; shell is Cowrie's emulation; HTTP templates use `string.Template` (no attribute access) | `sensor/honeypots/plugins/*`, test `test_http_device_template_cannot_reach_python_attributes` |
| Sensor used as a pivot | FTP never opens data connections (`PASV`/`PORT`/`EPRT` → 425); no proxying; DNS authoritative-only, never recursive | `plugins/ftp.py`, `plugins/dns.py` |
| Sensor used as a reflector | UDP replies: per-source token bucket (5/s, burst 10), global bucket (200/s), reply ≤ 10× request; suppressed replies are logged | `common/runtime.py::ReflectionGuard` |
| Adaptive control misuse | RL hardening can only select from five bounded effects; sensors ignore unknown effects and fail open; safety floor and `HARDENING_MODE=shadow/off` | `services/hardening.py`, `common/hardening.py` |
| Resource exhaustion | per-source concurrent TCP cap; per-connection message and lifetime bounds; bounded framing for every protocol; container `pids`/memory/CPU limits | `common/runtime.py`, `common/server.py`, `sensor/docker-compose.yml` |
| Container escape surface | read-only root FS, `cap_drop: [ALL]`, `no-new-privileges`, non-root UID 10001, no privileged container ports (Compose maps 502/21/53/554) | `sensor/docker-compose.yml`, persona validator |
| Passive monitor overreach | Zeek is opt-in, has only `NET_RAW`/`NET_ADMIN`, a BPF filter excludes management traffic (22, 5044, 41641, 8000) | `sensor/docker-compose.yml` |
| Index-mapping injection | Logstash copies v2 fields through explicit per-namespace whitelists (parity-tested with the Python reference) | `20-json-honeypots.conf`, `tests/ingestion/test_schema_v2.py` |

## API authentication and authorization

`API_KEYS="viewer:…,analyst:…,admin:…,sensor:…"` (the legacy `API_KEY` maps to
admin). Keys are compared in constant time and read per request, so rotation
needs no restart. The authorization surface is one table in
`backend/app/security.py`:

| Role | May |
| --- | --- |
| viewer | read everything except the audit trail |
| analyst | viewer + create/run experiments, run comparisons, test rules |
| admin | analyst + rule activation, persona edits, fleet assignments (`PUT /fleet/{id}`), honeypot start/stop, audit trail |
| sensor | `POST /sensors/heartbeat`, `GET /adaptation/posture` (RL hardening actions), `GET /personas/{id}/effective`, `GET /fleet/{id}/assignment`, nothing else |

With no keys configured, the API is open (isolated-lab default). Terminate TLS at
a reverse proxy. The console's server attaches `FRONTEND_API_KEY` (choose the
least role you need) or the legacy `API_KEY`.

## Audit

Every non-GET request and every 401/403 is appended to `trapsig-audit`
(principal, role, method, path, status, outcome, client IP). Keys are never
logged. Writes are best-effort: if Elasticsearch is down, the action itself
fails too, and the audit failure is logged.

## Management plane

The backend controls legacy decoys only through an SSH forced command that
whitelists `manage.sh <start|stop|restart> <known service>` and `status`
(`sensor/scripts/ssh-manage-wrapper.sh`, tested) for the seven device containers
(cowrie, camera, router, gateway, plc, building, nas). Persona *definitions* are pulled by sensors,
validated locally by the same validator, and fall back to the baked-in file.
A bad definition can never replace a good one.

## Fleet agents

* **Unprivileged.** On Linux and Pi OS Lite the agent runs as the system user
  `trapsig` under systemd, with only `CAP_NET_BIND_SERVICE` (for ports below 1024),
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and
  memory/task limits. On Windows it runs as `NT AUTHORITY\LocalService`.
* **Standard library only.** The agent is pure Python with no third-party
  dependencies on the device.
* **Ingest credentials.** Agents reach Logstash's HTTP input (:5045) with basic
  auth (`TRAPSIG_INGEST_USER`/`TRAPSIG_INGEST_PASSWORD`, change the default). They
  reach the API with a `sensor:` key, which can only heartbeat and read its
  assignment, posture and persona definitions.
* **Validated assignments.** An assignment is validated by the backend (known
  personas, no duplicates, no port clash per address) before any agent sees it;
  agents keep the last good assignment if the backend is unreachable.

## Secrets and data

Submitted credentials are research evidence and stay in the lab. Personas can set
`logging.credentials = "redact"`. The live stream masks passwords. The Pi
management key is mounted read-only and git-ignored. CI runs gitleaks, Trivy and
an SBOM.

## Known limitations

* All agents share one ingest password and the HTTP input has no TLS. Keep it on
  the isolated lab network, or put TLS in front of it. Per-device credentials or
  mTLS are on the roadmap.
* Shared-secret keys, not per-user identities; no SSO. Adequate for a lab, not
  a multi-tenant service.
* The analysis host's Elasticsearch runs without X-Pack security on loopback
  (`LOCAL_BIND_HOST`); do not bind it to a routable interface.
* The audit index is append-only by convention, not by WORM storage.
