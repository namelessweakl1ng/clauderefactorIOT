# Detection engines, explainability and comparison

Decision record: [ADR-0004](../adr/0004-multi-engine-detection.md), [ADR-0005](../adr/0005-grouped-evaluation.md).

The unit of detection is a **session**: one source IP's events inside the
inactivity timeout (default 300 s). Three engines read the same session and each
can emit *signals*; the hybrid detector merges them into one detection per
`(session, type)`. Detection IDs are unchanged from v1, so experiment
correlation and history remain valid.

| Engine | What it is | Explanation it gives | Confidence means |
| --- | --- | --- | --- |
| `rule` | Sigma-style YAML rules in `backend/app/rules/` | rule title, observed count vs threshold, **exact evidence events**, author ATT&CK tags | author-assigned prior (not a probability) |
| `ml` | multi-label logistic policy (`services/ml/`) | top feature contributions `weight × value` | per-head Platt-calibrated probability when the head was calibrated on a grouped split (`confidence_calibrated`), otherwise a raw logistic score |
| `anomaly` | isolation forest (`services/detection/anomaly.py`) | depth-weighted feature attribution vs training median (**heuristic**) | normalized isolation score |

`DETECTION_MODE` selects `hybrid` (default), `rules` or `ml`. Posture-based
sensitivity (`threshold_scale`) applies to learned heads only; rules are
deterministic.

## Rule format

```yaml
name: password-guessing            # kebab-case, unique; referenced by correlations
id: 3cf05878-2552-4974-abe8-e4c31eade2ec
title: Password guessing against one service
status: stable                     # stable | test | experimental | deprecated (off by default)
version: 1
level: high                        # informational | low | medium | high | critical
confidence: 0.85                   # author prior in (0, 1]
detection_type: BRUTE_FORCE        # UPPER_SNAKE_CASE; required when generate: true
tags: [attack.credential-access, attack.t1110.001]
falsepositives: [...]
correlation:                       # or `detection:` for an event rule
  type: event_count                # event_count | value_count | temporal | temporal_ordered
  rules: [authentication-failure]  # event rules (generate: false building blocks allowed)
  group_by: [service.name]
  timespan: 5m
  condition: {gte: 5}
tests:                             # executed by CI and GET /detection/rules/self-test
  - name: five failures in five seconds
    match: true
    events: [{event: {category: authentication, outcome: failure}, service: {name: cowrie}, repeat: 5}]
```

Event rules use Sigma selections: a mapping (AND) or list of mappings (OR) of
`field|modifier: value(s)`. Modifiers: `contains`, `startswith`, `endswith`, `re`,
`cidr`, `gt`, `gte`, `lt`, `lte`, `exists`, `all`, `cased`. Strings are
case-insensitive with `*`/`?` wildcards by default. Conditions support `and`,
`or`, `not`, parentheses, `1 of sel*`, `all of sel*`, `1 of them`, `all of them`.

One derived field exists and is documented: `trapsig.derived.known_default_credential`
(the shared public default-credential list also used by the ML feature and the
attack toolkit). Rules never depend on hidden logic.

Count windows are sliding (two-pointer), so `gte: 5` within `5m` fires on the
densest qualifying window and cites exactly those events. Upper-bound
conditions (`lt`/`lte`/`eq`) are evaluated over the whole group, because "fewer
than N within some window" is trivially true.

### Adding or changing a rule

1. Edit a file in `backend/app/rules/`, with at least one positive and one
   negative test (CI enforces this for generating rules).
2. `pytest tests/detection/test_rules.py`: every embedded case must pass, and
   every ATT&CK tag must exist in the catalogue.
3. The ruleset version (`rules-<hash>`) changes automatically, so new
   experiments land in a new evaluation cohort.

Activation is runtime state: `POST /detection/rules/{id}/state` (admin, audited)
writes `trapsig-rule-state`; the processor reloads it every cycle.

## ATT&CK

`services/detection/attack.py` holds a curated Enterprise+ICS subset that a
sensor can actually observe. Mappings are labelled `rule-tag` (asserted by a
rule author) or `type-default` (project default for an ML/anomaly type). Check
for drift against MITRE's STIX bundles with
`python -m backend.app.tools.verify_attack <bundle.json>...`. `GET /detection/attack`
returns coverage and observed counts.

## Anomaly engine

Fit with `python -m backend.app.tools.train_anomaly` on control-experiment
sessions (default) or `--all-sessions`. There is deliberately no synthetic
cold start, because novelty relative to invented data is meaningless; without a
model the engine is inactive. A documented deviation from the original paper:
points outside a tree's training bounding box are treated as isolated by one
split. Standard iForest is otherwise blind to features that were constant in
training, which is exactly the novel behaviour a honeypot cares about.

## Comparing engines

`python -m backend.app.tools.compare_detectors --source logged|synthetic` or
`POST /detection/comparisons`. The method:

* **GroupKFold** over experiment (logged) or attacker (synthetic), so no group
  spans folds; the report proves it (`groups_spanning_folds: 0`).
* **Positive-vs-control** per-class scores, as in [EVALUATION](../research/EVALUATION.md):
  other attack classes are not negatives; unexpected detections are counted
  separately.
* F1 = 2TP/(2TP+FP+FN), so a class an engine never predicts scores 0 rather
  than vanishing from the macro average.
* A naive random-split run of the trained ML engine is reported as
  `leakage_inflation` to quantify what leakage would have overstated.
* Latency is the per-session p50/p95 on the host; model size is serialized bytes.

Example (synthetic corpus, seed 20261126, 5 folds; illustrates the method only):

| engine | macro-F1 | alert F1 | alert FPR | p95 latency |
| --- | --- | --- | --- | --- |
| rules | 0.921 | 0.951 | 0.000 | 1.88 ms |
| ml (bootstrap, shipped) | 0.889 | 0.941 | 0.000 | 0.06 ms |
| ml (retrained per fold) | 0.993 | 0.993 | 0.000 | 0.06 ms |
| anomaly | 0.000 (no types) | 0.991 | 0.042 | 0.24 ms |
| hybrid | 1.000 | 0.991 | 0.042 | 1.94 ms |

Since feature schema 2 the ML engine has heads for the ICS, exploit,
malware-download and unauthorised-command classes, so it no longer scores 0 on
them (it was 0.768 macro-F1 before). A naive random split would overstate the
retrained model by +0.007, which is the measured leakage. **These are synthetic numbers.**
Synthetic labels partly encode rule thresholds, so rules are favoured. Only
logged experiments support claims about the platform.

## Promotion gate fix

`tools/train_detector.py` previously split validation data per session, which
leaked an experiment's sessions across train and validation. It now uses the
same grouped split (by experiment → batch → source).
