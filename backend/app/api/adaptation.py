"""Adaptive defence API: RL hardening state, decisions, learning, policy.

``GET /adaptation/posture`` is what sensors poll (sensor role). Everything else
feeds the Adaptive Defence dashboard: what the agent changed, why, what happened
afterwards, and what it has learned.
"""

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query

from ..elastic import store
from ..services import hardening as rl

router = APIRouter(prefix="/adaptation", tags=["adaptation"])
TRAINING_INDEX = "trapsig-hardening-training"
REPOSITORY_REPORT = Path(__file__).resolve().parents[3] / "evaluation/hardening/training-report.json"

@router.get("/posture")
async def posture() -> list[dict[str, Any]]:
    """Sources with an active hardening action: ``{source_ip, level, actions, decision_id}``."""
    documents = await store.search(rl.POSTURE_INDEX, size=1000, sort_field="updated_at", missing_index_is_empty=True)
    return [doc for doc in documents if doc.get("source_ip") and (doc.get("actions") or doc.get("level") not in (None, "normal"))]


@router.get("/decisions")
async def decisions(limit: int = Query(100, ge=1, le=1000), source_ip: str | None = None) -> list[dict[str, Any]]:
    """Hardening decisions, newest first: what changed, why, and the measured outcome."""
    query = {"term": {"source_ip": source_ip}} if source_ip else None
    return await store.search(rl.DECISIONS_INDEX, query, size=limit, sort_field="decided_at", missing_index_is_empty=True)


@router.get("/agent")
async def agent() -> dict[str, Any]:
    """Learned posteriors per context x action, plus summary learning statistics."""
    posteriors = await rl.HardeningAgent(store).load_posteriors()
    evaluated = [
        d
        for d in await store.search(rl.DECISIONS_INDEX, size=1000, sort_field="decided_at", missing_index_is_empty=True)
        if d.get("status") == "evaluated" and isinstance(d.get("outcome"), dict)
    ]
    evaluated.sort(key=lambda d: d.get("decided_at", ""))
    table = []
    for context, arms in posteriors.items():
        for action, arm in arms.items():
            table.append(
                {
                    "context": context,
                    "action": action,
                    "expected_reward": round(2 * rl.posterior_mean(arm) - 1, 4),
                    "outcomes": int(arm["n"]),
                    "mean_observed_reward": round(arm["reward_sum"] / arm["n"], 4) if arm["n"] else None,
                    "evidence": round(arm["alpha"] + arm["beta"] - 2.0, 2),
                    "prior_evidence": round(float(arm.get("prior_alpha", 1.0)) + float(arm.get("prior_beta", 1.0)) - 2.0, 2),
                    "alpha": round(arm["alpha"], 3),
                    "beta": round(arm["beta"], 3),
                }
            )
    rewards = [d["outcome"]["reward"] for d in evaluated]
    cumulative, running = [], 0.0
    for index, decision in enumerate(evaluated, start=1):
        running += decision["outcome"]["reward"]
        cumulative.append(
            {"at": decision.get("decided_at"), "n": index, "mean_reward": round(running / index, 4), "action": decision.get("outcome", {}).get("credited_to")}
        )
    best = {}
    for row in table:
        current = best.get(row["context"])
        if row["evidence"] > 0 and (current is None or row["expected_reward"] > current["expected_reward"]):
            best[row["context"]] = row
    document = None
    try:
        document = await store.get(rl.AGENT_INDEX, rl.AGENT_DOC_ID)
    except Exception:
        document = None
    return {
        "config": rl.config(),
        "contexts": list(rl.CONTEXTS),
        "trained": (document or {}).get("trained"),
        "actions": {action: list(effects) for action, effects in rl.EFFECTS.items()},
        "table": table,
        "best_action_by_context": {context: row["action"] for context, row in best.items()},
        "evaluated_decisions": len(evaluated),
        "mean_reward": round(sum(rewards) / len(rewards), 4) if rewards else None,
        "harm_rate": round(sum(d["outcome"]["harm_events"] > 0 for d in evaluated) / len(evaluated), 4) if evaluated else None,
        "learning_curve": cumulative[-200:],
    }


@router.get("/policy")
async def adaptive_policy() -> dict[str, Any]:
    """Human-readable definition of the agent, generated from live configuration."""
    cfg = rl.config()
    return {
        "kind": "contextual Thompson-sampling bandit (reinforcement learning with one-step episodes)",
        "mode": cfg["mode"],
        "state": "kill-chain stage (recon < credential < intrusion < ics_impact) x attack surface (it / ot) x new/returning: 16 contexts",
        "learning": [
            "hierarchical pooling: sparse contexts borrow up to 10 half-weighted outcomes from same-stage siblings",
            f"discounting: evidence decays by {cfg['discount']} per update in that context (tracks changing attackers)",
            f"per-source influence cap: after {cfg['source_cap']} outcomes a source's further outcomes are down-weighted",
            "offline pre-training on measured persona outcomes, installed only if it beats expert rules on held-out attacks",
        ],
        "actions": {action: list(effects) for action, effects in rl.EFFECTS.items()},
        "allowed_actions": cfg["allowed_actions"],
        "reward": "0.6 x new-behaviour intelligence + 0.4 x attacker still engaged - 1.0 x attacker success, clipped to [-1, 1]",
        "window_seconds": cfg["window_seconds"],
        "release_after_seconds": cfg["release_after_seconds"],
        "safety": [
            "once a source is manipulating process state (ics_impact) only write-blocking actions (read_only, quarantine) are chosen",
            "sensor-side hard limits: delay <= 0.5 s, per-source connection cap, no blocking, no service control",
            "sensors fail open to observe when the backend is unreachable",
            "HARDENING_MODE=shadow logs recommendations without enforcing them",
        ],
        "audit": "every decision, its reason and its measured outcome are stored in trapsig-hardening-decisions",
    }


@router.get("/training")
async def training() -> dict[str, Any]:
    """Latest offline training/evaluation report for the hardening agent."""
    reports = await store.search(TRAINING_INDEX, size=1, sort_field="generated_at", missing_index_is_empty=True)
    if reports:
        return {**reports[0], "origin": "elasticsearch"}
    if REPOSITORY_REPORT.exists():
        report = json.loads(REPOSITORY_REPORT.read_text(encoding="utf-8"))
        report.pop("posteriors", None)
        return {**report, "origin": "repository file (not installed: run train_hardening --apply)"}
    return {"origin": None, "detail": "no training report: run python -m evaluation.measure_hardening then python -m backend.app.tools.train_hardening"}
