# ADR-0008: Reinforcement-learning hardening agent (supersedes ADR-0007)

Status: accepted (2026-11-26)

## Context
ADR-0007 rejected an online learning controller because no reward was defined,
lab data are scarce, and safety needed hard limits. The project owner asked for
RL-driven hardening that is visible in the dashboard. This design answers each
objection instead of ignoring it.

| ADR-0007 objection | Answer in this design |
| --- | --- |
| Reward undefined | Defined from the attacker's own telemetry in a fixed window: `0.6·intel + 0.4·engaged − 1.0·harm`, where *harm* is any attacker success (login, shell command, accepted write, MQTT publish). Hardening must stop success while keeping the attacker engaged enough to reveal tooling; neither `observe` nor `quarantine` is trivially optimal. |
| Too little data | A **bandit** (one-step episodes), not a full MDP, over 8 discrete contexts × 5 actions = 40 arms. Thompson sampling is sample-efficient, and the simulated-environment test shows convergence within ~200 episodes. |
| Non-stationarity | Beta posteriors keep learning; per-context arms isolate stages. The learned table is visible on the dashboard, so drift is inspectable. |
| Safety | Actions are bounded sensor effects only (delay ≤ 0.5 s, auth refusal, write refusal, UDP silence); no blocking or service control; fail-open sensors; a hard safety floor (never `observe` during `ics_impact`); `HARDENING_ALLOWED_ACTIONS`; `HARDENING_MODE=shadow`. |
| Auditability | Every decision stores context, previous/new action, samples, posterior means of all alternatives, explore/exploit/safety flag, reason text and the measured outcome. Every sensor event carries the `hardening.decision_id` that shaped it. |

## Decision
Replace the rule-based posture state machine (`services/posture.py`, deleted)
with `services/hardening.py`. The processor runs one agent cycle per processing
cycle: evaluate finished decisions → update posteriors → decide for sources with
recent detections → release sources quiet for `HARDENING_RELEASE_SECONDS`.
The sensor-facing `GET /adaptation/posture` keeps its shape and adds `actions`
and `decision_id`, so older sensors (level-only) still behave sensibly.

## Consequences
+ The adaptive layer now learns from outcomes and explains itself.
+ `observe` remains an arm, so the agent can learn that watching is best early
  in an attack (recon), which a fixed escalation ladder never could.
− Rewards are proxies; an attacker script that ignores responses yields the same
  reward under every action. The comparison remains an experiment: run
  `condition: baseline` (`HARDENING_MODE=off`) versus `condition: rl-hardening` arms.
− Cowrie (third-party) does not enforce `deny_auth`/`read_only`; its sessions
  still provide context and outcomes.
