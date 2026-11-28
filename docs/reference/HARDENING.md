# Adaptive defence: reinforcement-learning hardening

Decision record: [ADR-0008](../adr/0008-rl-hardening-agent.md). Code:
`backend/app/services/hardening.py` (agent), `sensor/honeypots/common/hardening.py`
(sensor cache), `common/runtime.py` and the plugins (enforcement). Dashboard:
**Adaptive Defence**.

## The loop

```text
detections for source S ──► context = stage(S) | surface(S) | new/returning
                             │
           Thompson sampling over allowed actions (Beta posterior per context × action, pooled per stage)
                             │
        decision (action, reason, alternatives) ──► trapsig-posture ──► sensors poll (≤ 5 s)
                             │                                           │ enforce effects,
                             │                                           │ stamp hardening.decision_id
                  window (300 s) of S's telemetry ◄──────────────────────┘
                             │
        reward = 0.6·intel + 0.4·engaged − 1.0·harm  ──► posterior update ──► next decision
```

## Actions and what the sensors do

| Action | Effects | Enforcement |
| --- | --- | --- |
| `observe` | none | normal behaviour |
| `tarpit` | `tarpit` | 150–500 ms delay before each TCP connection is served |
| `deny_auth` | `deny_auth` | FTP/RTSP/HTTP-device/telnet/Redis logins fail even with valid honey-credentials; SNMP default communities stop answering; legacy camera/router/IoT/MQTT show their fake lockout |
| `read_only` | `read_only` | Modbus writes → exception 04; CoAP PUT/POST/DELETE → 4.03; S7 write/download/stop → refused; BACnet WriteProperty → error; CIP Set_Attribute → status 0x0F; tank-gauge `S` commands → 9999; SNMP SET → notWritable; Redis writes → `-READONLY` |
| `quarantine` | `tarpit`, `deny_auth`, `read_only`, `drop_udp` | all of the above, and UDP replies (CoAP/SSDP/DNS/SNMP/BACnet/SIP/TFTP) are withheld and logged as `reply_suppressed: hardening_drop_udp` |

## Context (state)

`<stage>|<surface>|<history>`, 16 contexts.

* `stage` is the furthest kill-chain step among the source's detections in the
  lookback window: `recon` (reconnaissance, enumeration, probing, anomaly) <
  `credential` (brute force, default credentials) < `intrusion` (exploit attempt,
  shell commands, malware download, multi-stage) < `ics_impact` (process writes on
  Modbus/S7/BACnet/CIP/tank gauge/CoAP, MQTT command injection, SNMP SET, Redis writes).
* `surface` is `ot` once the source touched an industrial or building-control
  decoy (Modbus, S7, BACnet, EtherNet/IP, tank gauge, CoAP), otherwise `it`.
* `history` is `returning` if the source was handled before, otherwise `new`.

## Learning

* **Hierarchical pooling.** A decision samples each arm from its own context's
  Beta posterior plus half of the evidence in same-stage sibling contexts, capped
  at 10 pseudo-outcomes. A context seen rarely, such as `ics_impact|ot|returning`,
  therefore starts from what its stage has taught. The decision reason says how
  much was borrowed.
* **Discounting** (`HARDENING_DISCOUNT`, default 0.995). Each update first decays
  that context's evidence towards the prior, so the agent follows attackers who
  change behaviour instead of freezing on what it learned months ago.
* **Per-source influence cap** (`HARDENING_SOURCE_CAP`, default 3). A source's
  outcomes in a context count fully three times, then with weight `3/(k+1)`. One
  persistent attacker cannot poison the policy (50 fake outcomes count as fewer
  than 15; see the tests).
* **v1 migration.** Stored `stage|history` posteriors seed both surfaces.

## Offline training (`ts-bandit-2`)

```bash
python -m evaluation.measure_hardening                 # measure every attack × action on the real personas
python -m backend.app.tools.train_hardening         # train, evaluate on held-out attacks, write the report
python -m backend.app.tools.train_hardening --apply # also store the report in ES; install the prior only if the gate passes
```

1. **Measure** (`evaluation/hardening/outcomes.json`). Every attack scenario that
   runs in-process (39 of them) is executed under each of the five actions, twice,
   against the real persona runtime with the action's effects enforced by the sensor
   code. The table records harm, distinct behaviours and engagement. Nothing in it is assumed.
2. **Simulate.** Attacker episodes sample those measured outcomes. Who the attackers
   are is *modelled* and stated in the report: bots (impatient, reinfect, some ICS
   scripts write on first contact), scanners (recon, return often) and operators
   (patient, escalate after success, try another attack when blocked). The friction
   of each action decides whether an impatient attacker leaves early.
3. **Evaluate on attacks never trained on.** About 30% of scenarios per (stage,
   surface) group are held out. Seven policies run the same 1,500 episode seeds;
   the learned policy is compared with the expert rule table (recon → observe,
   credential → deny_auth, intrusion/ics → read_only) by a paired 95% CI.
4. **Gate.** The prior is installed only if the learned policy *beats* the rules
   (CI lower bound > 0), does not raise the attacker-success rate, and never breaks
   the safety floor (in `ics_impact` only `read_only`/`quarantine`). An installed prior is capped at 20 pseudo-outcomes per arm, and
   live evidence is kept on top of it, so real outcomes keep moving the agent.

### Current result (HTR-ff4b3cd55057)

| Policy | Mean reward (95% CI) | Attacker success | Regret |
| --- | --- | --- | --- |
| learned (greedy) | +0.581 [+0.575, +0.588] | 0.0% | 0.009 |
| learned (thompson, keeps learning) | +0.567 [+0.560, +0.573] | 0.7% | 0.028 |
| untrained thompson | +0.555 [+0.547, +0.562] | 2.1% | 0.039 |
| expert rules | +0.566 [+0.558, +0.574] | 2.0% | 0.015 |
| always observe | +0.453 [+0.442, +0.464] | 14.6% | 0.130 |
| always quarantine | +0.563 [+0.556, +0.569] | 0.0% | 0.059 |
| random | +0.497 [+0.487, +0.508] | 8.9% | 0.102 |

Learned − expert rules: **+0.0060** per decision, paired 95% CI [-0.0001, +0.0120].
**Gate: FAILED (prior not installed by default).**

How to read it. The learned policy scores the highest reward of the seven, and
has zero attacker success and the lowest regret. It is therefore at least as good
as a carefully hand-written rule table, and found that table by itself. It does
not beat the rules by a margin the strict gate accepts, so `--apply` does not install the
prior by default. That is the honest outcome. With the 16-context state the bandit
cannot tell apart attacks whose best response differs: for example, held-out
`intrusion|it` attacks favour `observe`, while trained ones favour `quarantine`. A rule
table that encodes what each effect does is hard to beat there. Learning still
pays off where rules cannot help: adapting when attacker behaviour changes
(discounting), and under new personas or actions without anyone re-deriving rules.
The gate was fixed before the first run. The only changes between runs were two
corrections to the training setup, both in `docs/project/IMPLEMENTATION_LOG.md`: no discounting
in a stationary simulator, and first-contact ICS writes in the attacker model.


## Reward

Computed from the source's events during the decision window:

* **harm**: the attacker achieved something: a successful authentication
  (including an accepted SNMP community), a shell command (shells record commands
  only after login), an accepted write on any process protocol (Modbus, S7, BACnet,
  CIP, tank gauge, SNMP SET), a CoAP state change, an accepted Redis write or exploit
  primitive, or an MQTT publish.
* **intel**: distinct new behaviours `(service, action, target)` not seen from
  this source before the decision, divided by 8 and capped at 1.
* **engaged**: the attacker kept interacting.

`reward = clip(0.6·intel + 0.4·engaged − 1.0·harm, −1, 1)`, applied as a
fractional Beta update. Each outcome's arithmetic is stored with the decision
and shown on the dashboard.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HARDENING_MODE` | `enforce` | `enforce`, `shadow` (log recommendations, enforce `observe`, credit `observe`), `off` |
| `HARDENING_ALLOWED_ACTIONS` | all five | comma-separated subset |
| `HARDENING_WINDOW_SECONDS` | 300 | decision window / measurement period |
| `HARDENING_LOOKBACK_SECONDS` | 3600 | detections considered for the context |
| `HARDENING_RELEASE_SECONDS` | 1800 | quiet time before a source returns to `observe` |
| `HARDENING_DISCOUNT` | 0.995 | evidence decay per update in a context (0.9–1.0) |
| `HARDENING_SOURCE_CAP` | 3 | full-weight outcomes per source and context before down-weighting |
| `POSTURE_ELEVATED/LOCKED_THRESHOLD_SCALE` | 0.7 / 0.4 | learned-detector sensitivity for hardened sources |

## Evidence that it works (tests)

* `tests/backend/test_hardening.py::test_bandit_learns_the_best_action_per_context`:
  in a simulated environment the agent identifies the best action per context and
  chooses it in more than 60% of late episodes.
* `tests/safety/test_scenarios_against_personas.py::test_rl_hardening_changes_the_attacker_outcome`:
  for 11 attacks on 11 protocols (RTSP, Modbus, CoAP, FTP, telnet, S7, BACnet, CIP,
  tank gauge, SNMP, Redis), the real runner attacks the real personas. Unhardened, the attacker succeeds; with the agent's effect, harm is 0,
  the attacker is still engaged, the reward is higher, and every event carries
  the decision ID.
* `tests/backend/test_hardening_training.py`: pooling borrows only from the same
  stage and is capped; discounting lets the agent follow a changed population (a
  frozen agent does not); the influence cap limits poisoning; prior capping and
  live-evidence merging; and on a synthetic table with known answers, training
  finds the best action per context.

## Evaluating it scientifically

Run identical scenario batches under `condition: baseline` with `HARDENING_MODE=off`
and under `condition: rl-hardening` with the agent enforcing, then compare at
**Evaluation** (controlled comparison panel). Report attacker-success rates and detection recall per arm.
