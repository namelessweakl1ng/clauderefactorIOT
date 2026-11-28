# TRAPSIG Roadmap

Living document. `docs/project/IMPLEMENTATION_LOG.md` records what was actually done and
verified; this file records the audit, the target architecture and what is
outstanding. Architectural decisions are recorded as ADRs in `docs/adr/`.

## 1. Audit of the starting point (branch `main` @ `7381721`)

Baseline: **364 tests passing** (`pytest -q`, Python 3.13, no Docker on the
audit host, so container/integration jobs were not executed locally).

### Implemented and sound (kept)

| Area | Evidence | Verdict |
| --- | --- | --- |
| Raw-event immutability, dead-letter routing | `elk/logstash/pipelines/90-validation.conf`, templates | Keep. Correct research property. |
| Deterministic, idempotent derivation | `services/processor.py`, `sessionizer.py` content-derived IDs | Keep. Restart-safe, replica-safe with lease. |
| Experiment lifecycle and scientific result semantics | `api/experiments.py`, `services/experiments.py` (TP/FN/TN/FP/INCONCLUSIVE, settle, PIT correlation) | Keep and extend. Unusually rigorous. |
| Bounded sensor runtime | `sensor/honeypots/common/server.py` (size/time bounds, per-IP cap, fuzz tests) | Keep and generalise. |
| Container hardening on the Pi | `sensor/docker-compose.yml` (read-only, cap_drop ALL, pids/mem/cpu limits) | Keep. |
| Learned linear policy with per-feature reasons | `services/ml/` | Keep as the supervised engine. |
| Posture state machine + bounded deception | `services/posture.py`, `sensor/.../posture.py` | Keep; make policy declarative. |

### Partially implemented / weak

| Finding | Detail |
| --- | --- |
| **Rule-based detection was removed entirely.** | `detector.py` now only runs the learned policy. There is no curated, auditable rule layer, so evidence for every detection is "all event IDs in the session" — not the events that actually matched. Explainability is weaker than it looks. |
| **No ATT&CK mapping** anywhere. | Detection types are project-local labels only. |
| **No unsupervised/anomaly path.** | Novel behaviour that no head was trained for is silently missed. |
| **Train/test leakage risk.** | `rl/evaluation.py` splits examples, not *groups*; sessions from one experiment/attacker can land on both sides. |
| **Detection comparison is rule-baseline-vs-policy on synthetic data only** | and the doc itself admits the baseline scores ~1.0 by construction. |
| **Personas are hard-coded Python classes** (one per container). | No declarative device profile, no way to add a device without code. |
| **Protocol coverage**: SSH/Telnet (Cowrie), 2×HTTP, MQTT, one custom TCP. | No Modbus, CoAP, RTSP, FTP, UPnP/SSDP, DNS. TCP-only runtime, one request per connection (no multi-turn protocols such as FTP/RTSP). |
| **Event schema v1** lacks persona ID, connection/flow ID, transport (hard-coded `tcp` in Logstash), and any network-correlation key. |
| **No sensor registry/heartbeat.** | Sensor health = one SSH call to one `PI_HOST`; multi-sensor is impossible. |
| **API auth**: single shared key compared with `!=` (timing-unsafe), no roles, no audit trail of mutating calls. |
| **Experiments** lack objective/hypothesis, duplication, archiving, cross-cohort comparison, and a reproducible dataset bundle. |
| **No live streaming**; the UI is request/response only. |
| **Frontend**: functional but shaped around the old page list; no detection lab, threat-intel, sensor or comparison views. |

### Redundant / obsolete

* `docs/reference/PERSONAS.md` and `docs/reference/ARCHITECTURE.md` describe "feature-frozen" sensors and "deterministic rules" in places that no longer match the code.
* `HONEYPOTS` dict in `pi_manager.py` duplicates the persona inventory.

## 2. Target architecture (decisions summarised; see `docs/adr/`)

* **Stack stays**: Filebeat → Logstash → Elasticsearch → FastAPI → Next.js. No
  Kafka/NATS/Redis/Postgres: event volumes are lab-scale (≪1k events/s), ES is
  already the system of record and supports every query we need; adding a broker
  would add a second durability story with no measured benefit (ADR-0001).
* **Sensor**: protocol-plugin registry + declarative YAML device personas; one
  persona process can host several protocol services; TCP and UDP; bounded
  multi-turn conversations; UDP reflection guard (ADR-0002).
* **Schema v2**: additive (`persona.*`, `network.transport` from the sensor,
  `network.community_id`, `trapsig.connection_id`, per-protocol namespaces).
  v1 documents remain readable (ADR-0003).
* **Detection**: three engines behind one interface — Sigma-style rules,
  supervised linear policy, unsupervised isolation forest — plus a hybrid merge.
  Every detection carries per-engine signals, ATT&CK techniques and exact
  evidence (ADR-0004).
* **Comparison**: grouped cross-validation (groups = experiment / attacker)
  measuring per-class P/R/F1, macro-F1, FPR/FNR, latency and model size
  (ADR-0005).
* **Network intelligence**: optional Zeek on the sensor (Compose profile),
  correlated to honeypot events by Community ID (ADR-0006).
* **Sensor fleet**: authenticated heartbeats into `trapsig-sensors`.
* **Security**: role-based API keys (viewer/analyst/admin/sensor), constant-time
  comparison, append-only audit index.
* **Live ops**: Server-Sent Events from ES with a watermark (no broker).

## 3. Work plan and status

All 14 planned items are implemented; the per-item status, including what
could not be verified without Docker or hardware, is the table at the end of
`docs/project/IMPLEMENTATION_LOG.md`.

## 4. Outstanding work (next steps, in priority order)

1. **Run on infrastructure.** `docker compose up` on the analysis host and the
   Pi; confirm the Logstash v2 Ruby blocks and `30-zeek.conf` against real
   records (the CI `integration` job covers Logstash start-up only); pin the
   Zeek image by digest after verifying it on arm64.
2. **Collect logged evidence.** Run ≥5 repetitions per scenario under
   `baseline` and `adaptive-deception` conditions, then
   `compare_detectors --source logged --store`. Every result so far is synthetic.
3. ~~Scenarios for the new protocols~~: done (21 scenarios, closed-loop tested).
4. ~~Remote persona restart~~: done (each persona is a whitelisted container).
4a. **RL agent on real traffic.** First local arm comparison done (see
   `docs/project/IMPLEMENTATION_LOG.md` §11). Next: more repetitions on the physical fleet, then
   tune the reward weights only from that evidence.
4b. **RL state richer than 16 contexts.** The offline evaluation shows the bandit
   matches but cannot significantly beat an expert rule table, because attacks in
   one context have different best responses (e.g. `intrusion|it`). Candidate
   features: the protocol family touched, and whether a write/login already
   succeeded. Re-measure and re-gate after any change; keep the gate fixed.
4c. **Fleet hardening.** Agent auto-update (signed bundle from the backend), mTLS
   or per-device ingest credentials instead of one shared Logstash password, and a
   Docker image of the agent for hosts that prefer containers.
5. ~~Calibration~~: done. Platt scaling per head, fitted on a grouped calibration
   split, with ECE before/after in the training summary.
6. ~~Learned heads for new types~~: done. Feature schema 2 with ICS, exploit,
   download and discovery features and five new heads.
6a. **Faster cold start.** Training the bootstrap detector takes about 41 s on first use
   (`scripts/dev/benchmark.py`), and every test or fresh process that needs it
   pays that cost. Cache the trained bootstrap policy keyed by feature schema and seed.
7. **Typed coverage.** Remove the `services/evaluation.py` mypy exemption.
8. **Frontend tests.** Add component tests (e.g. Vitest + Testing Library) for
   the client actions; current frontend verification is lint/types/build plus
   an SSR smoke test.
9. ~~Degraded-mode latency~~: done. `ES_MAX_RETRIES` (default 1, was the
   client's 3) halves the time to fail while Elasticsearch is down (measured
   8.05 s → 4.05 s per call on the Windows dev host).
