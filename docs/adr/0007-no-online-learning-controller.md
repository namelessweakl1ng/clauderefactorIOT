# ADR-0007: Keep adaptive deception rule-based; evaluate it with experiment arms

Status: **superseded** by [ADR-0008](0008-rl-hardening-agent.md) (2026-11-26). Kept for the record of the objections ADR-0008 answers.

## Question
Should a reinforcement-learning agent or contextual bandit choose deception
responses (delay, fake lockout, persona variant) per source?

## Analysis
A learned controller needs, at minimum:

| Requirement | State in TRAPSIG | Consequence |
| --- | --- | --- |
| **State** | per-source detections, posture level, protocol mix — available | feasible |
| **Actions** | {none, delay, fake lockout, UDP silence} — small and bounded | feasible |
| **Reward** | "attacker engaged longer", "revealed more TTPs", "did not escalate"? Each is *delayed* (minutes–hours), *confounded* by attacker scripts that ignore responses, and partly *adversarial* (a scanner that stops may simply be finished) | **undefined** |
| **Data volume** | tens–hundreds of lab sessions per week; real Internet exposure is out of scope | far below what bandit regret bounds need for a 4-arm, multi-context problem |
| **Stationarity** | attacker tooling changes between runs by design | violates bandit assumptions |
| **Safety** | the controller would act on live services | needs hard limits regardless |

Without a defensible reward, any learned policy would optimise an arbitrary
proxy; its "improvement" could not be distinguished from noise at lab scale.

## Decision
* Keep the transparent state machine (`services/posture.py`), now exposed for
  audit at `GET /adaptation/policy`, with sensor-side **hard limits** (delay ≤
  0.5 s, per-source connection cap, no blocking, no service control, fail open).
* Answer "does adaptive deception help?" **experimentally**: run the same
  scenarios under `condition: baseline` (posture effects disabled, e.g.
  `POSTURE_*_THRESHOLD_SCALE=1` and sensors without `BACKEND_URL`) and
  `condition: adaptive-deception`, then use `GET /experiment-lab/compare`
  (Fisher exact test, Wilson intervals, confounder warnings).
* Revisit a contextual bandit only when (1) a reward has been validated in such
  A/B experiments, (2) ≥ several hundred conclusive sessions per context exist,
  and (3) it can run **offline** first (off-policy evaluation on logged
  decisions) behind the same hard limits.

## Known interaction
The hybrid detector can emit more detection types per session than the learned
policy alone, so posture may escalate sooner. This is a measurable effect, not a
silent change: compare `DETECTION_MODE=ml` and `hybrid` arms.
