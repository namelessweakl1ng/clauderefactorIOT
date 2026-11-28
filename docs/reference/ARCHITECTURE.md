# Architecture

> **v2 summary.** A fleet of sensor devices (a Pi plus Linux/Windows hosts) runs
> 16 declarative multi-service **persona** devices. Each device runs the fleet agent
> (`sensor/honeypots/agent.py`), which pulls its assignment from the backend and
> ships events over HTTP. The single-Pi Docker mode (Cowrie plus the six original
> persona containers, shipped by Filebeat) still works, as does an optional passive
> **Zeek** monitor. Logstash normalizes
> honeypot telemetry into schema v1/v2 `trapsig-events-*` and Zeek records into
> `trapsig-network-*`. The FastAPI processor reconstructs sessions and runs the
> **hybrid detector** (Sigma-style rules + learned policy + isolation forest; see
> [DETECTION](DETECTION.md)), then the **RL hardening agent** ([HARDENING](HARDENING.md)) learns from finished decisions and chooses per-source hardening. Sensors send
> authenticated heartbeats. All state lives in Elasticsearch. Each decision is
> recorded in [`docs/adr/`](../adr/): no broker (0001), plugins and personas (0002),
> schema v2 (0003), multi-engine detection (0004), grouped evaluation (0005),
> Zeek + Community ID (0006), and the RL hardening agent (0008, superseding 0007).
> Security boundaries are in [SECURITY](SECURITY.md).
>
> The sections below describe the learned-policy and processor internals, which
> v2 keeps. The rule-based *posture state machine* they mention was replaced by
> the RL agent (ADR-0008). Where they say rules were removed, read: the
> *fixed-threshold rule baseline* inside the learned policy was replaced. A
> separate, auditable rule engine was added back in v2 as one of three engines.

## Component map (v2)

| Component | Runs on | Responsibility |
| --- | --- | --- |
| Fleet agent (`sensor/honeypots/agent.py`) | every sensor device | runs the device's assigned personas, hot-reloads on change, caches the assignment offline, ships JSONL to Logstash over HTTP with persisted offsets |
| Persona runtime (`sensor/honeypots/common/runtime.py`) | sensor | hosts all services of one persona; bounds, UDP guard, schema-v2 envelopes, heartbeat, hardening enforcement |
| Protocol plugins (`sensor/honeypots/plugins/`) | sensor | framing + parsing + bounded replies for 19 protocols, socket-free unit tests |
| Zeek (`--profile netmon`) | Pi, host network | passive conn/dns/http/ssl logs with Community ID |
| Filebeat | Pi (Docker mode) | durable disk queue to Logstash (Beats :5044) |
| Logstash (`elk/logstash/pipelines/`) | analysis | inputs Beats :5044 and HTTP :5045 (agents, basic auth); normalize, whitelist v2 namespaces, validate, dead-letter, route Zeek |
| Elasticsearch | analysis | immutable raw events + derived indices (templates in `elk/elasticsearch/`) |
| Processor (`services/processor.py`) | analysis | incremental (event.ingested watermark): sessions → hybrid detection → RL hardening; single writer via lease |
| Fleet (`services/fleet.py`, `api/fleet.py`) | analysis | persona-to-device assignments, port-conflict validation, what each agent pulls |
| RL hardening (`services/hardening.py`, `hardening_sim.py`) | analysis | per-source hardening decisions, outcome learning, offline training and gate |
| Detection (`services/detection/`, `services/detector.py`) | analysis | rules, ATT&CK, anomaly, hybrid merge, comparison framework |
| Experiment lab (`api/experiments.py`, `services/experiment_lab.py`) | analysis | lifecycle, ground truth, arm statistics, datasets |
| Security (`security.py`) | analysis | RBAC policy table, audit |
| Console (`frontend/`) | analysis | presentation over the API; SSE live view |

## Request and data flow for one interaction

1. A Modbus write reaches the `plc` container (host 502 → container 5020).
2. The runtime frames it (MBAP), and the plugin applies it to a connection-local
   overlay and replies. The runtime writes a v2 envelope with persona, Community
   ID, connection ID and sequence.
3. Filebeat ships it. Logstash copies the whitelisted `modbus.*` keys and
   validates the record, which lands in `trapsig-events-YYYY.MM.dd`.
4. If Zeek runs, the same flow appears in `trapsig-network-*` with the same
   Community ID.
5. The processor's next cycle reconstructs the session; rule `modbus-write`
   fires with the exact write event as evidence and ATT&CK T0855/T0836.
6. The RL agent picks a hardening action for the source (e.g. `read_only`, so the
   next write returns exception 04), sensors apply it within seconds, and after
   the window the measured outcome updates the agent.
7. If an experiment is running, finishing it correlates exactly these events,
   sessions and detections, producing TP/FN/TN/FP/INCONCLUSIVE.

## v1 foundations (still in force)

In the original (Docker-mode) design there are two hosts. The Pi runs five containers representing six logical services (Cowrie supplies SSH and Telnet) plus Filebeat. Filebeat's disk queue is the sole edge buffer and sends JSON/JSONL over Beats to laptop Logstash. Per-family filters normalize records into the canonical schema; malformed records go to `trapsig-dead-letter-*`, never silently disappear.

Elasticsearch owns date-based `trapsig-events-*` raw indices and the stable derived indices `trapsig-sessions`, `trapsig-detections`, `trapsig-experiments`, plus the adaptation indices `trapsig-policy`, `trapsig-posture`, and `trapsig-hardening-events`. FastAPI is the only domain backend. Its focused routers query Elasticsearch, while services deterministically reconstruct source-IP sessions, classify them with a learned explainable policy, maintain per-source hardening posture, correlate experiments, and invoke a fixed Pi management script through SSH. Next.js contains only presentation and a typed HTTP client. Kibana directly explores Elasticsearch for detailed research analysis.

The deployment deliberately has only the components in this document; no parallel messaging, storage, API, or collector exists. A model lifecycle now exists, but it is deliberately minimal: offline/batch training writes immutable policy generations to Elasticsearch and the live processor reads the latest one — no online/inline weight updates.

## Learned detection policy

Detection is a small **multi-label linear policy**: one logistic head per detection type (`backend/app/services/ml/`), all sharing one feature vector computed from a session while its `events` are still attached (so training and live inference see identical features). A head fires when `sigmoid(w·x + b) >= threshold`. No rule-based decision logic remains in the detection path; domain knowledge survives only as feature *inputs* (e.g. "is this a publicly known default credential pair", from a single shared list the attack toolkit also uses).

Framing, stated plainly: each head is a contextual-bandit arm with a deterministic ±1 correctness reward (did firing match the experiment's known ground truth?). The batch policy-gradient update for that reward reduces exactly to reward-weighted logistic regression, which is what `rl/training.py` implements — ordinary supervised correction, not a full sequential-MDP deep-RL system. The model stays interpretable: each detection's reason is built from the top per-feature contributions (`weight × value`), preserving the "reasons and evidence IDs, no opaque score" contract, now with an added confidence and the firing policy generation.

Training is **offline/batch only**. `backend/app/tools/train_detector.py` pulls completed experiments, re-derives their sessions from raw events, labels them (attack → expected head = 1; control → every head = 0; inconclusive skipped), optionally merges the deterministic synthetic bootstrap set at a lower weight, trains, and writes a new timestamped `trapsig-policy` generation. The processor reads the most recent generation each cycle (one cheap `size=1` search) and falls back to the in-process deterministic bootstrap policy when none exists or ES is unreachable, so `detect(session)` stays a plain synchronous call. Cold start is a seeded, reproducible synthetic set — no wall-clock randomness — so repeated boots behave identically.

## Hardening (RL agent)

The rule-based posture state machine (`posture.py`) described in earlier versions
was **removed**. Per-source hardening is now chosen by the RL agent in
`backend/app/services/hardening.py` (ADR-0008); see [HARDENING](HARDENING.md) for
its contexts, actions, reward, safety floor and training. What stays from the
earlier design:

- The current action per source is one `trapsig-posture` document. Sensors poll
  `/adaptation/posture`, enforce the effects (tarpit, refuse logins, read-only,
  withheld UDP replies), and stamp `hardening.decision_id` on their events.
- **Detection sensitivity.** A hardened source's learned-detector threshold is
  scaled (`POSTURE_ELEVATED/LOCKED_THRESHOLD_SCALE`).
- **No service control.** Hardening never starts or stops services or blocks IPs.
- **Self-DoS bound.** The tarpit delay is at most 0.5 s per connection, and a
  per-source concurrent-connection cap (`SENSOR_MAX_CONNECTIONS_PER_IP`, default
  24) sheds a pathological source.
- **Fail-open.** The sensor's posture poller keeps its last-known-good cache (or
  `observe`) on any error, and never blocks a connection on a network hiccup.
- **Off really means off.** `HARDENING_MODE=off` actively releases every posture.
- **Cowrie.** Cowrie is a vendored third-party project; Cowrie-side hardening is
  not wired.

## Evaluation, promotion gate, and baseline

A trained generation is only adopted if it is actually good. `rl/evaluation.py`
computes per-head precision/recall/F1 and calibration (Brier score, expected
calibration error) on a held-out split, and `tools/train_detector.py` runs a
**promotion gate**: a candidate becomes the `active` generation only if its
held-out macro-F1 does not regress versus the incumbent (bootstrap when none
exists); otherwise it is stored as an inactive `candidate` so the history stays
complete. `tools/evaluate_detector.py` reports the learned policy against the frozen
pre-rework **rule baseline** (`rl/baseline.py`, offline only). Honest caveat: on
the synthetic bootstrap set the rule baseline scores ~1.0 because that data is
*defined* by those thresholds; the meaningful comparison is on logged experiment
data, where the learned policy can diverge from and improve on the fixed rules.

## Operational robustness

- **Single-writer**: `rl`-adjacent `services/leader.py` is an Elasticsearch lease
  (optimistic-concurrency compare-and-set with a TTL) so that, with multiple
  backend replicas, exactly one runs the materializing processor loop. It
  fail-opens to "leader" for the simple stores used in tests. Set
  `PROCESSOR_ENABLED=false` to make a replica API-only.
- **Retention**: an ILM policy (`elk/elasticsearch/ilm/trapsig-retention.json`,
  default 30-day delete) bounds the dated `trapsig-events-*` and
  `trapsig-dead-letter-*` indices so a long-running lab does not fill the disk.
- **Optional API auth**: setting `API_KEY` requires the `X-API-Key` header on
  every request (health, readiness, metrics, and docs exempt); the frontend
  forwards it. TLS is expected at a reverse proxy.
- **Observability**: `GET /metrics` emits Prometheus text (counts, dead-letter
  volume, processor liveness/leadership, active-policy age); `GET /health/live`
  and `GET /health/ready` are orchestration probes; `LOG_FORMAT=json` switches to
  structured logs.
- **Parser safety**: the honeypot parsers are fuzz-tested against random and
  boundary input, and a per-source concurrent-connection cap
  (`SENSOR_MAX_CONNECTIONS_PER_IP`) bounds connection floods and the tarpit delay.

## Custom honeypot runtime

The camera, router, IoT TCP service, and MQTT decoys use a small shared socket runtime. It owns bounded connection lifecycle and JSONL persistence, assembles size-limited HTTP requests across reads, reads one bounded IoT line, and assembles one bounded MQTT frame using Remaining Length. Separate persona modules own parsing and replies. Camera and router are stateful bounded HTTP personas with expiring in-memory sessions; IoT is a bounded line protocol; MQTT is a bounded framing/parser emulation. `app.py` is only the explicit dispatcher. Cowrie is an independent runtime providing the SSH/Telnet VEG-200 low-interaction emulated shell.

## Data lifecycle

1. A bounded interaction reaches a Pi decoy.
2. The decoy writes structured JSONL (Cowrie writes its native JSON).
3. Filebeat annotates and durably queues the record.
4. Logstash parses, normalizes and indexes it or dead-letters it.
5. Session jobs use source IP and a configurable inactivity timeout (default five minutes).
6. The learned policy returns reasons and evidence IDs plus a confidence; no opaque score is surfaced.
7. Experiments reference matching immutable telemetry rather than altering it.

## Derived-data processor

FastAPI starts one lightweight asynchronous processor with its application lifespan. Every configured interval it reads the events *ingested* since its persisted watermark (`trapsig-processor-state`), takes only their source IPs, and re-sessionizes those sources from the start of any session still open for them. It then upserts sessions and detections under stable content-derived IDs. Cost per cycle follows new activity, not index size; backlogs drain oldest-first in `PROCESSING_BATCH_EVENTS` chunks; a 30 s re-read overlap covers events that become searchable late. Stores without point-in-time paging (test doubles) use a bounded window of the newest events instead. Repeating a cycle after a restart overwrites the same derived documents instead of duplicating them. The processor never updates event documents. Its last run, error, and write counts are exposed through `/system/status`.

## Telemetry integrity

An idempotent `elasticsearch-setup` Compose job installs explicit templates before
Logstash starts. Normalized schema-v1 records enter daily immutable raw event indices;
validation failures enter daily dead-letter indices. The processor reads but never
updates raw records and filters loopback/internal telemetry before creating schema-v1
sessions and detections. `/system/status` reports dead-letter volume (zero when no
index exists). Existing schema-less historical documents remain readable.


## Where to read the code

1. `sensor/docker-compose.yml` defines the fixed Pi topology and boundaries.
2. `sensor/honeypots/app.py`, then `common/server.py`, show dispatch, bounded reads, lifecycle, and logging.
3. Individual persona directories define protocol behavior; `cowrie/` owns SSH/Telnet identity.
4. `sensor/filebeat/filebeat.yml`, `elk/logstash/pipelines/`, and Elasticsearch templates show collection, normalization, validation, and storage.
5. Backend `processor.py`/`sessionizer.py`, then `detector.py`, show derived sessions and explainable detections.
6. Experiment routers and `evaluation/` show ground truth, cohorts, metrics, and reports.
7. `frontend/src/lib/api.ts` and pages show presentation over the sole API.
8. `attacks/runner/run.py` shows target validation usage and persona-aware bounded traffic.

See `PERSONAS.md` for file-level persona ownership and fidelity limits.
