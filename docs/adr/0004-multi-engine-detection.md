# ADR-0004: Multi-engine, explainable detection

Status: accepted (2026-11-26)

## Context
Detection had become a learned linear policy only. Its "evidence" was every
event in the session; there was no curated rule layer, no ATT&CK mapping, and no
novelty detection.

## Decision
Three engines share one session interface and one detection document:

1. **Rules** — a Sigma-*inspired* YAML format (`detection-rules/`): Sigma's
   metadata (`id`, `title`, `status`, `level`, `tags: attack.tXXXX`,
   `falsepositives`), Sigma's selection/condition grammar and value modifiers
   (`contains|startswith|endswith|re|cidr|gt|gte|lt|lte|exists|all`), and a
   session-scoped aggregation modelled on Sigma *correlation* types
   (`event_count`, `value_count`). Implemented from the specification; no pySigma
   code (LGPL, and its backend-conversion focus is not what we need — we evaluate
   in-process). Every rule carries embedded positive/negative test cases that CI
   executes.
2. **Supervised** — the existing linear policy (unchanged contract).
3. **Anomaly** — a deterministic pure-Python Isolation Forest over the same
   feature vector, trained offline, persisted like policies.

Hybrid merge: one detection per `(session, type)` (ID unchanged, so experiment
correlation and history stay valid) with `signals[]` listing each engine that
fired, its score, reason and evidence. `fired_by` is the engine list. Rule
evidence is the exact matching event IDs.

Confidence wording: rule confidence is an author-assigned prior; ML confidence is
a logistic output reported as *uncalibrated* unless the comparison report shows
calibration (Brier/ECE) was evaluated.
