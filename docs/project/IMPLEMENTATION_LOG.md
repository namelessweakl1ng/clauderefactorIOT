# Implementation log

Chronological record of the v2 transformation on branch `transform/platform-v2`.
Every entry states what was verified and how. "Verified" means exercised by an
automated test or a recorded command on the development host (Windows 11, Python
3.13, Node 26). Docker, Elasticsearch, Logstash and Raspberry Pi hardware were
**not available** on that host; anything that depends on them is marked
*unverified on infrastructure*.

## Baseline (before any change)

* `pytest -q`: **364 passed**.
* Audit findings: see `docs/project/ROADMAP.md` §1.

## Work completed

### 1. Audit, roadmap, ADRs (commit `e36cb47`)
Audit of all docs and code against behaviour; reference repositories studied at
source level (RIoTPot service/middleware/plugins, OpenCanary modules, Conpot
templates (GPL-2, so ideas only), EventHorizon pits/Prometheus, T-Pot and its
attack map watermark, Sigma rules and pySigma conditions/correlations/modifiers).
Zeek and attack-stix-data were not in the provided reference clone; their
integration follows their published formats (Zeek JSON logs, Community ID spec,
STIX attack-pattern objects).

### 2. Detection engines (commit `f67d53b`)
* Sigma-spec rule engine, 34-rule IoT pack, **71 embedded test cases, all pass**.
* ATT&CK catalogue + STIX drift verifier.
* Isolation forest (pure Python, deterministic) with a documented out-of-range
  modification. The first test run showed standard iForest scoring a never-seen
  command burst at 0.48 (below the threshold), which motivated the change.
* Hybrid detector with per-engine signals; IDs unchanged.
* Grouped-CV comparison. The first run exposed a metric bug (classes an engine
  never predicts vanished from macro-F1, flattering ML at 0.994); fixed so they
  score F1 = 0 (ML then 0.768).
* **Bug fixed:** promotion-gate validation split leaked sessions across
  experiments; now grouped.

### 3. Sensor runtime, plugins, personas (commit `550e040`)
* Plugin contract, multi-service runtime, UDP reflection guard, seven new
  protocol plugins, legacy adapters (behaviour-equivalence test), six personas.
* **Bugs fixed:** pipelined line reads were silently dropped (socket objects
  have `__slots__`); token bucket mishandled negative elapsed time.
* **Bug fixed:** the posture poller sent no API key, so with auth enabled every
  poll returned 401 and deception silently never engaged.
* Real-socket end-to-end test (Modbus TCP, CoAP UDP, FTP pipelined) passes.

### 4. API surface (commit `bad9946`)
RBAC + audit (constant-time key comparison replacing `!=`), detection lab,
sensors, personas, network correlation, SSE stream, audit endpoint.

### 5. Ingestion (commit `6b8f89c`)
Schema v2 through Logstash (whitelisted namespaces, transport, version),
Zeek pipeline and routing, Filebeat inputs, typed templates for seven new
indices, Compose `personas`/`netmon` profiles, CLIs.
* **Hazard avoided:** re-declaring `confidence`/`policy_version` in the
  detection mapping upgrade would have conflicted with v1's dynamic mappings and
  failed the setup job, blocking the whole stack.
* Parity test proves the Logstash whitelist equals the Python reference.
* *Unverified on infrastructure:* Logstash Ruby blocks and the Zeek container
  were not executed (no Docker). The CI `integration` job exercises Logstash.

### 6. Experiment laboratory + adaptive policy (commit `f9a2b5a`)
Design fields, extended start snapshot, duplicate/archive/dataset, arm
comparison (Fisher exact verified against SciPy's documented value), adaptive
policy endpoint, ADR-0007 (no online learning controller, with reasons).

### 7. Frontend (commit `427e33e`)
Regrouped research console with six new pages and rebuilt detections,
honeypots and observability pages; client actions for rules, personas,
comparisons and arm comparison; SSE live view.
* `eslint`, `tsc --noEmit`, `next build`: clean.
* Smoke test: real backend with Elasticsearch unreachable plus production
  frontend; **all 14 pages HTTP 200** with explicit error/empty states; rule
  self-test renders 71/71 through the UI; SSE passes through the proxy.
* *Unverified:* visual review in a browser against live data.

### 8. Documentation (this commit)
README rewritten around v2; new DETECTION.md and SECURITY.md; v2 sections in
EVENT_SCHEMA, PERSONAS, EXPERIMENTS, ARCHITECTURE; ROADMAP status.

### 9. Round 2: scenarios, RL hardening, simplification
* **Attack scenarios (commit `ddf5700`):** 21 new campaign scenarios (41 total) and a
  protocol executor module (Modbus, CoAP, RTSP, FTP, SSDP, DNS), with per-step
  ports, path/credential lists, MQTT publish and bounded pacing. Closed-loop
  test: **19/19** persona-targeting scenarios produce exactly their expected
  outcome through the real runner, personas, normalizer and detector. The two
  SSH campaigns need Cowrie (*unverified locally*).
* **Simplification:** the four single-service legacy containers and the
  `SERVICE=` path were removed. Every decoy is one persona container (camera,
  router, gateway, plc, building, nas) that keeps every legacy port and
  `service.name`. Five historical or superseded docs were deleted. Kibana is
  opt-in (`--profile kibana`, saves ~1.5 GB RAM). `.gitattributes` pins LF for
  scripts and configs.
* **RL hardening:** the rule-based posture state machine was replaced by a
  contextual Thompson-sampling bandit (`services/hardening.py`, ADR-0008):
  * 8 contexts (kill-chain stage x new/returning) x 5 bounded actions;
  * reward from the attacker's own subsequent telemetry;
  * safety floor, shadow/off modes, every decision audited with reason,
    alternatives and measured outcome;
  * sensors enforce `tarpit`/`deny_auth`/`read_only`/`drop_udp` and stamp
    `hardening.decision_id` on events (whitelisted end to end).
* **Verified:**
  * learning test (finds the best action per context, chooses it in more
    than 60% of late episodes);
  * real-stack test (4 attack chains succeed unhardened and have zero harm
    when hardened, with a higher reward);
  * agent store-cycle and API tests.
* The Adaptive Defence page now shows the hardened sources, what changed and
  why, the learned context x action table, the learning curve and the
  definitions.

### 10. Frontend consolidation and Evaluation rebuild
* 14 pages reduced to 10:
  * Events and Sessions became **Investigate**;
  * Threat Intel's ATT&CK matrix moved into Detection Lab;
  * Network moved into Observability;
  * Arm Comparison moved into Evaluation.
* Overview rewritten: activity, detections, recent hardening changes and fleet
  health. Kibana buttons removed because Kibana is optional.
* **Evaluation** now shows:
  * cohort detection metrics and per-type recall/precision;
  * coverage of all 41 scenarios, with ones lacking lab evidence flagged;
  * RL containment (attacker-success rate per hardening action, observed vs hardened);
  * the latest engine comparison;
  * the controlled arm comparison.
* Dead chart components and types removed.
* Verified: eslint, tsc and next build clean. All 11 routes return 200 against the
  real backend with ES down; the removed routes return 404.

### 11. Round 3: multi-device fleet, 10 new personas, RL v2, scalability, naming

**Why.** All personas on one sensor share its IP, which is unrealistic and limits
the device count. The fleet available is one Raspberry Pi (Pi OS Lite) and three
hosts that may run Linux or Windows.

* **Naming.** Several names no longer said what the code does:
  * `services/rl/` was the supervised detector, not RL, and became `services/ml/`;
  * `train_policy` / `evaluate_policy` became `train_detector` / `evaluate_detector`;
  * the sensor's `posture.py` became `hardening.py`;
  * `DETECTOR_RULESET_VERSION` became `DETECTOR_VERSION`;
  * the model-history endpoint moved to `/detection/model-history`.
* **Protocols and personas.** There are 11 new emulators (S7comm, BACnet/IP,
  EtherNet/IP+CIP, tank gauge, BusyBox telnet, SNMP v1/v2c, Redis, SIP, TFTP, VNC,
  RDP), modelled on the reference honeypots' wire behaviour (Conpot, GasPot, Dionaea,
  Heralding, RDPY-style cookie capture) and written from scratch. They are used by
  10 new personas, for 16 in total, and covered by 20 new rules (UUIDv5 IDs).
* **Detector.** Feature schema 2 adds 10 features and 5 new heads: exploit,
  malware download, unauthorised command, ICS reconnaissance and ICS write.
  Platt calibration is fitted on a grouped calibration split.
  * Two bugs fixed: F1 is now `2tp/(2tp+fp+fn)`, and the promotion gate no longer
    activates a model it cannot measure.
* **Fleet** (`/fleet`, `sensor/fleet.toml`, `sensor/honeypots/agent.py`):
  * central assignment with per-IP, wildcard-aware port-conflict validation;
  * one stdlib-only agent for all three OSes. It hot-reloads on an assignment
    fingerprint, caches the last assignment offline, and ships events to a new
    Logstash HTTP input (:5045) with persisted offsets. `install` writes a systemd
    unit (CAP_NET_BIND_SERVICE, sandboxed) or a Windows LocalService task, and
    `check` test-binds every port;
  * console editor on Sensors & Personas.
  * **Verified live:** an event shipped by `agent.Shipper` was normalised to
    schema v2 by the real Logstash 8.19 pipeline and indexed within seconds.
* **Scenarios.** 26 new scenarios (23 attacks, 3 controls), for 67 in total. All
  26 pass the closed loop (runner → personas → normalizer → detector). The
  in-process lab moved to `attacks/runner/inprocess.py`; it patches only the
  runner's pacing (the old global `time.sleep` patch also silenced sensor tarpits).
* **RL v2** (`ts-bandit-2`):
  * 16 contexts (stage × IT/OT surface × history);
  * hierarchical pooling, discounting and a per-source influence cap;
  * harm/behaviour coverage for every new protocol;
  * two enforcement gaps closed: SNMP ignored `deny_auth`/`read_only`, and CIP
    ignored `read_only`.
* **RL training:**
  * `evaluation/measure_hardening.py` measured 39 attacks × 5 actions × 2 repeats on
    the real persona runtime;
  * `hardening_sim` and `train_hardening` train on that table, evaluate 7 policies
    on held-out attacks with common seeds, and gate on a paired CI against expert
    rules.
  * **Run 1:** the learned policy was −0.008 vs rules. Diagnosis: (a) training used
    the live discount in a stationary simulator, and (b) the attacker model had no
    first-contact ICS writes, so `ics_impact|*|new` never trained. Both were
    fixed; the gate was unchanged.
  * **Run 2 (HTR-75dd425f22d9):** the learned policy scored +0.581, the best of the
    seven, with 0 % attacker success and regret 0.009 (rules: 0.015). Against the
    rules it is +0.006 with a paired CI of [−0.0001, +0.012], so the gate **fails
    narrowly** and the prior is not installed by default. No further reruns, to
    avoid optional stopping.
* **Scalability.** The processor is incremental, using an `event.ingested`
  watermark:
  * only affected sources are re-sessionized, and open sessions are rebuilt whole
    (the old newest-10,000 scan truncated them);
  * late events are caught and backlogs drain in batches.
* **Evidence tooling:** `evaluation/arm_outcomes.py`, which scores attacker success per arm.
* **Docs:** `docs/guides/DEPLOYMENT.md` (multi-device), `docs/reference/HARDENING.md` (v2 +
  results), `docs/reference/SCENARIOS.md` (now generated and tested), README.

#### Evidence: local arm comparison (real ES/Logstash/Filebeat, virtual Pi)

**Setup.**
* Real Elasticsearch, Logstash and Filebeat 8.19 with the repo's pipelines.
* All 16 personas on 172.23.64.1, a Hyper-V adapter unreachable from the LAN.
* One attacker address, 172.23.64.1.
* 12 attacks + 3 controls on the new protocols, × 2 repetitions per arm, shuffled
  with seed 1127 and a 30 s gap between runs.
* Arms: `baseline` (`HARDENING_MODE=off`) and `rl-hardening` (`enforce`). The agent
  was **untrained**: the trained prior is not installed because its gate failed.
* Batches: `LOCAL-OTIT-BASELINE-3` + `LOCAL-OTIT-S7-BASELINE` and `LOCAL-OTIT-RL-3`
  + `LOCAL-OTIT-S7-RL`. Per-run records and `LOCAL-OTIT-arm-outcomes.json` are in
  `evaluation/results/` (local, git-ignored by policy).

**Defence** (`python -m evaluation.arm_outcomes`). Attacker success is every attack
run's own events scored with the agent's harm definition:

| Arm | Attack runs scored | Attacker succeeded | Wilson 95% CI | Runs hardened |
| --- | --- | --- | --- | --- |
| baseline | 24 | 16 (67%) | 47–82% | 1 (see caveats) |
| rl-hardening | 24 | **2 (8%)** | 2–26% | 22 |

Fisher exact p = 5.8 × 10⁻⁵. No control produced harm in either arm. In baseline,
every attack that can achieve something succeeded: logins, shell commands, and
S7/BACnet/CIP/tank-gauge/SNMP/Redis writes. The 8 unsuccessful baseline runs are
pure probes with nothing to achieve (RDP cookie, SIP OPTIONS, refused TFTP, S7 SZL
read).

**Detection** (`/experiment-lab/compare`). Recall was 100% in both arms on
scorable runs and there were no false positives (main batches: baseline TP 20 /
TN 4, RL TP 16 / TN 4; S7 batches: TP 4 / TN 2 in each). Hardening did not hide
attackers from detection.

**Caveats; read them with the numbers.**
1. *Carry-over.* With one attacker address, a posture set after the first detection
   persists (30 min release), so most RL runs met a source that was already
   hardened. This measures "once a source is flagged, hardening stops its further
   attacks". It does **not** show per-attack action quality, which the offline
   held-out evaluation addresses.
2. *Both RL failures are one exploration choice.* In `ics_impact|ot|returning` the
   untrained agent explored `deny_auth`. S7 has no login, so the PLC stop
   succeeded in both repetitions. The safety floor now allows only write-blocking
   actions (`read_only`, `quarantine`) in `ics_impact`, with a regression test.
   These two runs were measured **before** that change.
3. *Unscorable for detection.* The 4 DVR runs the agent blocked are `INCONCLUSIVE`
   for detection, because ground truth requires the attack to complete. They are
   scored for defence.
4. *One contaminated run.* The RL arm's quarantine was still active for the first
   S7 baseline run (a probe; no harm possible either way). The script waited
   30 s; the release took one more cycle.
5. *Scale and venue.* n = 24 attack runs per arm, a virtual Pi on one Windows host,
   not the physical fleet.

**Bugs the runs found and fixed** (each has a regression test). Every earlier
batch is invalid and was set aside under `*-INVALID-*`:
* `fe5eb93` (processor): the incremental processor's ingest lag hid a run's own
  events from `finish()`, producing false negatives.
* `7d58d05` (rl): `HARDENING_MODE=off` never released postures, so the
  "baseline" was silently hardened by a stale `deny_auth`. This also invalidates
  the earlier `LOCAL-BASELINE-1` batch.
* `ea7f2fa` (experiments): an experiment orphaned by a crash blocked every later
  experiment. Such runs are now abandoned after `EXPERIMENT_STALE_SECONDS`, and
  the 409 names the blocker.
* `f77b549` (scenarios): S7 mapped to the plugin name instead of `service.name`,
  so the experiment query matched no events.
* Safety floor (this commit): only write-blocking actions are allowed in
  `ics_impact`.

After the floor change, the offline report was regenerated (HTR-ff4b3cd55057).
The learned policy is unchanged (+0.581, 0% harm, regret 0.009, gate still fails
by CI [−0.0001, +0.012]). The still-learning live agent's attacker success
dropped from 1.4% to 0.7%.

### 12. Repository organisation

**Why.** The project had grown hard to navigate: helper scripts for four
different audiences in one flat folder, three places for tools, 12 flat docs
with no index, no folder that explained itself, and a 320-line README that mixed
the front page with full procedures.

* `scripts/` is grouped by job: `lab/` (one-PC lab), `pi/` (Tailscale connect),
  `analysis-host/` (Docker stack up/down/status), `dev/` (tests, validation,
  preflight, benchmark, scenario catalogue) and `ci/`. Each moved script's own
  path assumptions were updated.
* `measure_hardening` moved to `evaluation/`, next to the other evidence tools
  (`python -m evaluation.measure_hardening`).
* `docs/` is grouped by purpose: `guides/` (set it up), `reference/` (how it
  works), `research/` (how to measure it), `project/` (ROADMAP and this log, moved
  from the root) and `adr/`. `docs/README.md` is the index.
* Every top-level folder has a README: what it holds, where to start, and its
  commands.
* The root README is now a front page (193 lines): a folder map, three ways to
  start, the architecture with the fleet, common tasks, evidence so far, and safety.
* **Docs brought up to date:**
  * ARCHITECTURE: fleet agent, HTTP ingest, incremental processor; the removed
    posture state machine is replaced by what runs now.
  * PERSONAS: all 16, generated from the TOML files, plus fidelity limits for the
    11 new plugins.
  * EVENT_SCHEMA: namespace list generated from `V2_NAMESPACES`.
  * DETECTION: calibration, and a rerun synthetic engine comparison.
  * EXPERIMENTS: the RL-arm procedure actually used, with its pitfalls.
  * SECURITY: fleet agents, the sensor role, the shared ingest password as a known
    limitation.
  * SETUP and CONNECT_AND_DEMO: pointers to the fleet guide.
  * `attacks/README`: it wrongly claimed six fixed ports.
* **New test** (`tests/test_docs_links.py`): every relative link in every tracked
  Markdown file must resolve, and every top-level folder must have a README.
* **Fixed:** `scripts/dev/benchmark.py` had been broken by the processor's
  `refresh=` argument (its fake store did not accept it).

## Final verification (this host)

| Check | Result |
| --- | --- |
| `pytest -q` | **637 passed** (round 3; baseline 364) |
| `ruff check backend attacks evaluation tests sensor` | clean |
| `mypy` (24 files incl. `hardening.py`, `hardening_sim.py`, `processor.py`, `fleet.py`) | clean |
| frontend `eslint` / `tsc` / `next build` | clean |
| `compare_detectors --source synthetic` | runs in ~13 s; report labelled synthetic |

## Status by work item

| # | Item | Status |
| --- | --- | --- |
| 1 | Audit, roadmap, ADRs | ✅ done |
| 2 | Rule engine, pack, tests, ATT&CK | ✅ done & tested |
| 3 | Hybrid detection | ✅ done & tested |
| 4 | Plugins, personas, new protocols | ✅ 16 personas, 19 protocols; all run in the local lab through real Logstash/ES; 🟡 no physical-fleet run yet |
| 5 | Schema v2 ingestion | ✅ code + contract tests; 🟡 Logstash runtime unverified locally |
| 6 | Anomaly engine | ✅ done & tested |
| 7 | Comparison framework | ✅ done & tested |
| 8 | Heartbeats, RBAC, audit | ✅ done & tested |
| 9 | Zeek + Community ID | ✅ correlation tested; 🟡 Zeek container unverified |
| 10 | Experiment lab | ✅ done & tested |
| 11 | Adaptive defence | ✅ RL v2, offline training + gate (fails narrowly; prior not installed), lab arm comparison: attacker success 67% → 8% (p = 5.8e-5), recall unchanged; 🟡 one attacker IP, n = 24/arm |
| 12 | Live SSE | ✅ done; smoke-tested through proxy |
| 13 | Frontend | ✅ built + smoke-tested; 🟡 no visual review against live data |
| 14 | Docs | ✅ done |
| 15 | Realistic attack scenarios | ✅ 67 scenarios; all persona scenarios closed-loop tested; 15 run end to end in the lab; 🟡 Cowrie campaigns need Docker |
| 17 | Multi-device fleet | ✅ agent + `/fleet` + console editor; HTTP ingest verified against real Logstash; 🟡 not yet on the physical Pi/Windows hosts |
| 16 | Simplification | ✅ one container per persona, legacy path and stale docs removed, Kibana optional |
