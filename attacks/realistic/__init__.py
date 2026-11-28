"""Realistic, varied -- but non-adaptive -- lab attack toolkit.

These standalone scripts generate more realistic traffic than the fixed-step YAML
scenarios (multi-threaded, randomized timing, real bounded wordlists, varied
payloads), so the learned detector trains on genuinely varied positive examples.

Non-negotiable safety, identical to the existing runner: every script takes
exactly one explicit ``--target`` validated to a single usable host inside
``LAB_SUBNET`` via :func:`attacks.runner.safety.validate_target`. Nothing scans a
range, persists, creates C2, or exfiltrates data.

The attacker logic is intentionally straightforward and does **not** adapt to the
honeypot's responses mid-run, so evaluation stays reproducible. Each script emits
a runner-compatible result summary (``run_id``, ``target``, timestamps, per-step
outcomes, and a declared ``expected_detection``) -- see
:mod:`attacks.realistic.common` for how that maps to a training label.
"""
