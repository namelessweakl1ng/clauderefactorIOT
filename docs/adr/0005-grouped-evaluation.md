# ADR-0005: Grouped cross-validation for detection comparison

Status: accepted (2026-11-26)

Sessions from the same experiment, batch or attacker are correlated; random
splits leak. The comparison framework uses deterministic GroupKFold with the
group key `experiment_id` → `evaluation_batch_id` → `source_ip` (first present).
Rules are not trained, so they are evaluated on the same held-out folds for a
like-for-like comparison. Reports include per-class P/R/F1, macro-F1, FPR, FNR,
per-session latency (p50/p95) and model size, and state the data provenance
(`logged` vs `synthetic`). Synthetic-only results are labelled as such because
synthetic labels are partly defined by rule thresholds (circular).
