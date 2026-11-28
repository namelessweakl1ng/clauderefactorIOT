"""Reinforcement-learning hardening: a contextual Thompson-sampling bandit.

What it controls
----------------
For every active attacker source the agent picks one **hardening action** that
the sensors enforce for a bounded window (``HARDENING_WINDOW_SECONDS``):

==============  ===============================================================
``observe``     no change (maximum intelligence, attacker may succeed)
``tarpit``      150-500 ms delay per connection
``deny_auth``   every login fails, even with valid honey-credentials
``read_only``   Modbus/CoAP state changes are refused with protocol errors
``quarantine``  tarpit + deny_auth + read_only + UDP replies withheld
==============  ===============================================================

Every effect is enforced sensor-side under hard limits (delay <= 0.5 s,
per-source connection cap, no blocking, no service control) and fails open.

State (context)
---------------
``<stage>|<surface>|<history>``: the attacker's furthest kill-chain stage in the
lookback window (``recon`` < ``credential`` < ``intrusion`` < ``ics_impact``,
derived from detection types), the attack surface (``ot`` once the source touched
an industrial or building-control decoy, else ``it``), and whether the source was
already handled (``new`` / ``returning``). Sixteen discrete contexts stay small
enough to read on the dashboard.

Learning
--------
* **Hierarchical pooling.** A context's arm is sampled from its own Beta
  posterior plus half of the evidence its sibling contexts (same stage) hold,
  capped at ``POOL_CAP`` pseudo-outcomes. A rarely seen context such as
  ``ics_impact|ot|returning`` starts from what the stage taught, and its own data
  dominates as soon as it has any.
* **Discounting.** Each update first shrinks that context's evidence towards the
  prior by ``HARDENING_DISCOUNT`` (default 0.995), so the agent tracks attacker
  populations that change over weeks instead of freezing on old behaviour.
* **Per-source influence cap.** After ``HARDENING_SOURCE_CAP`` outcomes from the
  same source in the same context, further outcomes from it are down-weighted
  (``cap / (k + 1)``): one persistent attacker cannot steer the policy for
  everyone (reward poisoning).
* **Offline training.** ``python -m backend.app.tools.train_hardening`` trains on
  a simulator whose outcome table is *measured* against the real personas
  (``evaluation/measure_hardening.py``), evaluates on held-out attacks against
  fixed baselines, and only installs the learned prior (capped at ``PRIOR_CAP``
  pseudo-outcomes per arm, so live data still moves it) if it passes the gate.

Reward
------
Measured from the source's own telemetry during the decision window:

    harm    = 1 if the attacker achieved anything (successful login, shell
              command, accepted Modbus/CoAP write, MQTT publish), else 0
    intel   = distinct new behaviours observed (service, action, target) / 8, capped at 1
    engaged = 1 if the attacker kept interacting at all
    reward  = clip(0.6*intel + 0.4*engaged - 1.0*harm, -1, 1)

A honeypot that is "hardened well" stops the attacker from succeeding while
still keeping them engaged long enough to reveal their tooling, which is why
neither ``observe`` (harm) nor ``quarantine`` (attacker leaves, little intel) is
trivially optimal. The best trade-off differs per stage, which is what the bandit
learns. Rewards in [-1, 1] are mapped to [0, 1] and applied as a fractional Beta
update (alpha += p, beta += 1 - p).

Safety
------
* ``HARDENING_MODE``: ``enforce`` (default), ``shadow`` (decide and log, but
  sensors keep ``observe``; only the observe arm is updated, since that is what ran),
  or ``off``.
* ``HARDENING_ALLOWED_ACTIONS`` restricts the arms.
* Safety floor: in ``ics_impact`` the agent may only choose actions that include
  ``read_only`` (``read_only``, ``quarantine``). ``observe``, ``tarpit`` and
  ``deny_auth`` would let a write on a login-less industrial protocol succeed
  again; a lab run showed an explored ``deny_auth`` letting an S7 PLC stop through.
  The reason string says so.
* Decisions are deterministic given (source, time, agent version), auditable, and
  bounded in time; with no new activity a source is released back to ``observe``.
"""

from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Iterable

AGENT_INDEX = "trapsig-hardening-agent"
DECISIONS_INDEX = "trapsig-hardening-decisions"
POSTURE_INDEX = "trapsig-posture"
AGENT_DOC_ID = "agent-v1"
AGENT_VERSION = "ts-bandit-2"

ACTIONS = ("observe", "tarpit", "deny_auth", "read_only", "quarantine")
EFFECTS: dict[str, tuple[str, ...]] = {
    "observe": (),
    "tarpit": ("tarpit",),
    "deny_auth": ("deny_auth",),
    "read_only": ("read_only",),
    "quarantine": ("tarpit", "deny_auth", "read_only", "drop_udp"),
}
# Sensor/legacy compatibility: the level the older personas and the detector's
# sensitivity scaling understand.
LEVELS = {"observe": "normal", "tarpit": "elevated", "read_only": "elevated", "deny_auth": "locked", "quarantine": "locked"}
STAGES = ("recon", "credential", "intrusion", "ics_impact")
SURFACES = ("it", "ot")
# Services whose decoys are industrial or building control (service.name or honeypot.type).
OT_HONEYPOTS = frozenset({"modbus", "s7comm", "s7", "bacnet", "enip", "atg", "coap"})
STAGE_OF_TYPE = {
    "RECONNAISSANCE": "recon",
    "WEB_ENUMERATION": "recon",
    "MQTT_PROBING": "recon",
    "ICS_RECONNAISSANCE": "recon",
    "MULTI_SERVICE_ACTIVITY": "recon",
    "ANOMALOUS_BEHAVIOUR": "recon",
    "BRUTE_FORCE": "credential",
    "DEFAULT_CREDENTIALS": "credential",
    "EXPLOIT_ATTEMPT": "intrusion",
    "COMMAND_INTERACTION": "intrusion",
    "MALWARE_DOWNLOAD": "intrusion",
    "MULTI_STAGE_ATTACK": "intrusion",
    "UNAUTHORIZED_COMMAND": "ics_impact",
    "ICS_WRITE": "ics_impact",
}
REWARD_WEIGHTS = {"intel": 0.6, "engaged": 0.4, "harm": 1.0}
INTEL_SATURATION = 8
POOL_WEIGHT = 0.5
ARM_KEYS = ("alpha", "beta", "n", "reward_sum", "prior_n", "prior_alpha", "prior_beta")
POOL_CAP = 10.0
PRIOR_CAP = 20.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def config() -> dict[str, Any]:
    allowed = [a.strip() for a in os.getenv("HARDENING_ALLOWED_ACTIONS", ",".join(ACTIONS)).split(",") if a.strip() in ACTIONS]
    mode = os.getenv("HARDENING_MODE", "enforce").lower()
    return {
        "mode": mode if mode in {"enforce", "shadow", "off"} else "enforce",
        "allowed_actions": allowed or ["observe"],
        "window_seconds": int(os.getenv("HARDENING_WINDOW_SECONDS", "300")),
        "lookback_seconds": int(os.getenv("HARDENING_LOOKBACK_SECONDS", "3600")),
        "release_after_seconds": int(os.getenv("HARDENING_RELEASE_SECONDS", "1800")),
        "safety_floor": {"ics_impact": "only actions with read_only (read_only, quarantine)"},
        "reward_weights": dict(REWARD_WEIGHTS),
        "discount": min(1.0, max(0.9, float(os.getenv("HARDENING_DISCOUNT", "0.995")))),
        "source_cap": max(1, int(os.getenv("HARDENING_SOURCE_CAP", "3"))),
        "pool_weight": POOL_WEIGHT,
        "pool_cap": POOL_CAP,
        "agent_version": AGENT_VERSION,
    }


# --------------------------------------------------------------------------- #
# Pure logic (unit-testable without a store)
# --------------------------------------------------------------------------- #


def stage_for(detection_types: Iterable[str]) -> str:
    ranks = [STAGES.index(STAGE_OF_TYPE[t]) for t in detection_types if t in STAGE_OF_TYPE]
    return STAGES[max(ranks)] if ranks else "recon"


def context_key(stage: str, returning: bool, surface: str = "it") -> str:
    return f"{stage}|{surface}|{'returning' if returning else 'new'}"


CONTEXTS = tuple(context_key(stage, returning, surface) for stage in STAGES for surface in SURFACES for returning in (False, True))


def empty_posteriors() -> dict[str, dict[str, dict[str, float]]]:
    return {context: {action: {"alpha": 1.0, "beta": 1.0, "n": 0, "reward_sum": 0.0} for action in ACTIONS} for context in CONTEXTS}


def posterior_mean(arm: dict[str, float]) -> float:
    return arm["alpha"] / (arm["alpha"] + arm["beta"])


def pooled_arm(posteriors: dict[str, dict[str, dict[str, float]]], context: str, action: str) -> dict[str, float]:
    """The context's own posterior plus capped, half-weighted evidence from same-stage siblings."""
    stage = context.split("|", 1)[0]
    borrowed_a = borrowed_b = 0.0
    for other, arms in posteriors.items():
        if other != context and other.split("|", 1)[0] == stage:
            borrowed_a += arms[action]["alpha"] - 1.0
            borrowed_b += arms[action]["beta"] - 1.0
    total = borrowed_a + borrowed_b
    scale = POOL_WEIGHT if total * POOL_WEIGHT <= POOL_CAP else (POOL_CAP / total if total else 0.0)
    own = posteriors[context][action]
    return {"alpha": own["alpha"] + scale * borrowed_a, "beta": own["beta"] + scale * borrowed_b, "borrowed": round(scale * total, 3), "n": own["n"]}


def allowed_for(context: str, allowed: list[str]) -> tuple[list[str], str | None]:
    """Safety floor: once a source manipulates process state, only write-blocking actions.

    Industrial protocols (Modbus, S7, BACnet, CIP, tank gauges) have no login, so
    tarpit or deny_auth cannot stop a write; only actions carrying ``read_only``
    can. Exploration continues, but only among those.
    """
    if context.startswith("ics_impact"):
        blocking = [a for a in allowed if "read_only" in EFFECTS[a]]
        if blocking and len(blocking) < len(allowed):
            return blocking, "safety floor: once process state is being manipulated only write-blocking actions (read_only, quarantine) are allowed"
    return list(allowed), None


def choose(context: str, posteriors: dict[str, dict[str, dict[str, float]]], allowed: list[str], rng: random.Random) -> dict[str, Any]:
    """Thompson sampling over the allowed arms of one context."""
    arms = {action: pooled_arm(posteriors, context, action) for action in ACTIONS}
    candidates, safety = allowed_for(context, allowed)
    samples = {action: rng.betavariate(arms[action]["alpha"], arms[action]["beta"]) for action in candidates}
    means = {action: round(posterior_mean(arms[action]), 4) for action in ACTIONS}
    chosen = max(samples, key=lambda a: (samples[a], -ACTIONS.index(a)))
    best_mean = max(candidates, key=lambda a: (means[a], -ACTIONS.index(a)))
    mode = "exploit" if chosen == best_mean else "explore"
    n = int(arms[chosen]["n"])
    borrowed = arms[chosen]["borrowed"]
    evidence = f"{n} outcome(s)" + (f" + {borrowed:.1f} pooled from the {context.split('|')[0]} stage" if borrowed else "")
    if mode == "exploit":
        why = f"{chosen} has the best expected reward in context {context} ({means[chosen]:.2f} from {evidence})"
    else:
        why = (
            f"exploring {chosen} (sampled {samples[chosen]:.2f}; expected {means[chosen]:.2f} from {evidence}) "
            f"instead of the current best {best_mean} ({means[best_mean]:.2f}); uncertainty is still high"
        )
    if safety:
        why += f"; {safety}"
    return {"action": chosen, "chosen_by": mode, "samples": {k: round(v, 4) for k, v in samples.items()}, "means": means, "reason": why, "safety": safety}


# (namespace, field) pairs that identify *what* an event touched, most specific first.
BEHAVIOUR_TARGETS: tuple[tuple[str, str], ...] = (
    ("url", "path"),
    ("process", "command_line"),
    ("mqtt", "topic"),
    ("coap", "uri_path"),
    ("rtsp", "path"),
    ("ftp", "command"),
    ("dns", "qname"),
    ("modbus", "function_code"),
    ("iot", "operation"),
    ("s7", "function"),
    ("bacnet", "property"),
    ("bacnet", "service"),
    ("enip", "command"),
    ("atg", "command"),
    ("snmp", "community"),
    ("redis", "command"),
    ("sip", "method"),
    ("tftp", "filename"),
    ("rdp", "cookie_user"),
    ("vnc", "client_version"),
)
# Protocols whose events carry ``<ns>.write``: an accepted write is a process/config change.
WRITE_NAMESPACES = ("modbus", "s7", "bacnet", "enip", "atg", "snmp")


def behaviour_key(event: dict[str, Any]) -> tuple[str, ...]:
    target = ""
    for namespace, field in BEHAVIOUR_TARGETS:
        value = (event.get(namespace) or {}).get(field)
        if value not in (None, ""):
            target = str(value)
            break
    return ((event.get("service") or {}).get("name") or "?", (event.get("event") or {}).get("action") or "?", target[:120])


def is_harm(event: dict[str, Any]) -> bool:
    """Did the attacker achieve something the decoy let succeed?"""
    ev = event.get("event") or {}
    success = ev.get("outcome") == "success"
    if ev.get("category") == "authentication" and success:
        return True
    if ev.get("category") == "process" and (event.get("process") or {}).get("command_line"):
        return True  # shells only record commands after a successful login
    if success and any((event.get(ns) or {}).get("write") for ns in WRITE_NAMESPACES):
        return True
    redis = event.get("redis") or {}
    if success and (redis.get("write") or redis.get("exploit")):
        return True
    coap = event.get("coap") or {}
    if coap.get("state_change") and str(coap.get("response_code", "")).startswith("2."):
        return True
    if (event.get("mqtt") or {}).get("operation") == "publish":
        return True
    return False


def surface_for(honeypots: Iterable[str]) -> str:
    """``ot`` once a source touched any industrial/building-control decoy, else ``it``."""
    return "ot" if any(str(h).replace("-", "_") in OT_HONEYPOTS for h in honeypots if h) else "it"


def score_outcome(events: list[dict[str, Any]], prior_behaviours: set[tuple[str, ...]] | None = None) -> dict[str, Any]:
    prior = prior_behaviours or set()
    behaviours = {behaviour_key(e) for e in events}
    new = behaviours - prior
    harm = sum(is_harm(e) for e in events)
    intel = min(1.0, len(new) / INTEL_SATURATION)
    engaged = 1.0 if events else 0.0
    reward = REWARD_WEIGHTS["intel"] * intel + REWARD_WEIGHTS["engaged"] * engaged - REWARD_WEIGHTS["harm"] * min(1.0, harm)
    reward = max(-1.0, min(1.0, reward))
    return {
        "reward": round(reward, 4),
        "intel": round(intel, 4),
        "new_behaviours": len(new),
        "engaged": engaged,
        "harm_events": harm,
        "events": len(events),
        "explanation": (
            f"{len(events)} event(s), {len(new)} new behaviour(s), {harm} attacker success(es) -> "
            f"reward {reward:+.2f} = 0.6x{intel:.2f} intel + 0.4x{engaged:.0f} engaged - 1.0x{min(1, harm)} harm"
        ),
    }


def update(posteriors: dict[str, dict[str, dict[str, float]]], context: str, action: str, reward: float, *, weight: float = 1.0, discount: float = 1.0) -> None:
    """Fractional Beta update; ``discount`` < 1 first decays this context's evidence towards the prior."""
    if discount < 1.0:
        for other in posteriors[context].values():
            other["alpha"] = 1.0 + discount * (other["alpha"] - 1.0)
            other["beta"] = 1.0 + discount * (other["beta"] - 1.0)
    arm = posteriors[context][action]
    p = (reward + 1.0) / 2.0
    arm["alpha"] += weight * p
    arm["beta"] += weight * (1.0 - p)
    arm["n"] = int(arm["n"]) + 1
    arm["reward_sum"] = float(arm["reward_sum"]) + reward


def influence_weight(prior_outcomes: int, cap: int) -> float:
    """1 for a source's first ``cap`` outcomes in a context, then cap/(k+1)."""
    return 1.0 if prior_outcomes < cap else cap / (prior_outcomes + 1)


def cap_prior(posteriors: dict[str, dict[str, dict[str, float]]], cap: float = PRIOR_CAP) -> dict[str, dict[str, dict[str, float]]]:
    """Scale trained evidence so no arm carries more than ``cap`` pseudo-outcomes."""
    out = empty_posteriors()
    for context, arms in posteriors.items():
        for action, arm in arms.items():
            evidence = arm["alpha"] + arm["beta"] - 2.0
            scale = min(1.0, cap / evidence) if evidence > 0 else 1.0
            alpha, beta = 1.0 + scale * (arm["alpha"] - 1.0), 1.0 + scale * (arm["beta"] - 1.0)
            out[context][action].update(alpha=alpha, beta=beta, n=0, reward_sum=0.0, prior_n=int(arm.get("n", 0)), prior_alpha=alpha, prior_beta=beta)
    return out


# --------------------------------------------------------------------------- #
# Store-backed agent (used by the processor)
# --------------------------------------------------------------------------- #


class HardeningAgent:
    def __init__(self, store: Any) -> None:
        self.store = store

    async def _search(self, index: str, query: dict[str, Any] | None = None, size: int = 1000, sort_field: str = "@timestamp") -> list[dict[str, Any]]:
        try:
            try:
                return await self.store.search(index, query, size=size, sort_field=sort_field, missing_index_is_empty=True)
            except TypeError:
                return await self.store.search(index, query, size=size, sort_field=sort_field)
        except Exception:
            return []

    async def load_posteriors(self) -> dict[str, dict[str, dict[str, float]]]:
        document = None
        try:
            document = await self.store.get(AGENT_INDEX, AGENT_DOC_ID) if hasattr(self.store, "get") else None
        except Exception:
            document = None
        posteriors = empty_posteriors()
        for context, arms in ((document or {}).get("posteriors") or {}).items():
            parts = context.split("|")
            # v1 contexts were <stage>|<history>: seed both surfaces from them.
            targets = [context_key(parts[0], parts[1] == "returning", s) for s in SURFACES] if len(parts) == 2 else [context]
            for target in targets:
                for action, arm in (arms or {}).items():
                    if target in posteriors and action in posteriors[target]:
                        posteriors[target][action].update({k: arm[k] for k in ARM_KEYS if k in arm})
        return posteriors

    async def _agent_meta(self) -> dict[str, Any]:
        """Keep the training provenance of an installed prior across live updates."""
        try:
            document = await self.store.get(AGENT_INDEX, AGENT_DOC_ID) if hasattr(self.store, "get") else None
        except Exception:
            document = None
        return {"trained": document["trained"]} if document and document.get("trained") else {}

    async def current_levels(self) -> dict[str, str]:
        documents = await self._search(POSTURE_INDEX, size=1000, sort_field="updated_at")
        return {d["source_ip"]: d.get("level", "normal") for d in documents if d.get("source_ip")}

    async def _source_events(self, source_ip: str, start: str, end: str) -> list[dict[str, Any]]:
        query = {
            "bool": {
                "filter": [
                    {"bool": {"should": [{"term": {"source.ip": source_ip}}, {"term": {"source.ip.keyword": source_ip}}], "minimum_should_match": 1}},
                    {"range": {"@timestamp": {"gte": start, "lte": end}}},
                ]
            }
        }
        try:
            return await self.store.search_all("trapsig-events-*", query, sort=[{"@timestamp": "asc"}], missing_index_is_empty=True)
        except Exception:
            return []

    async def step(self, detections: list[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
        """One agent cycle: evaluate finished decisions, then decide for active sources."""
        cfg = config()
        now = now or _now()
        if cfg["mode"] == "off":
            # "off" must mean unhardened sensors: release anything a previous
            # enforce run left behind, or a baseline arm is silently hardened.
            released = []
            for doc in await self._search(POSTURE_INDEX, size=1000, sort_field="updated_at"):
                if doc.get("source_ip") and (doc.get("actions") or doc.get("action", "observe") != "observe"):
                    await self._write_posture(doc["source_ip"], "observe", None, now)
                    released.append(
                        {
                            "source_ip": doc["source_ip"],
                            "action": "observe",
                            "previous_action": doc.get("action"),
                            "released": True,
                            "reason": "HARDENING_MODE=off",
                        }
                    )
            return released
        posteriors = await self.load_posteriors()
        decisions = await self._search(DECISIONS_INDEX, size=2000, sort_field="decided_at")
        active = {d["source_ip"]: d for d in decisions if d.get("status") == "active"}
        handled_before = {d["source_ip"] for d in decisions if d.get("status") in {"evaluated", "released"}}
        changed: list[dict[str, Any]] = []

        # 1. Learn from decisions whose window has ended.
        for source_ip, decision in list(active.items()):
            expires = _parse(decision.get("expires_at"))
            if expires is None or expires > now:
                continue
            during = await self._source_events(source_ip, decision["decided_at"], decision["expires_at"])
            before = await self._source_events(source_ip, (now - timedelta(seconds=cfg["lookback_seconds"])).isoformat(), decision["decided_at"])
            outcome = score_outcome(during, {behaviour_key(e) for e in before})
            learned_action = decision["action"] if decision.get("mode") == "enforce" else "observe"
            context = decision["context"] if decision["context"] in posteriors else context_key(*_legacy(decision["context"]))
            prior = sum(1 for d in decisions if d.get("source_ip") == source_ip and d.get("context") == decision["context"] and d.get("status") == "evaluated")
            weight = influence_weight(prior, cfg["source_cap"])
            update(posteriors, context, learned_action, outcome["reward"], weight=weight, discount=cfg["discount"])
            decision.update(status="evaluated", outcome={**outcome, "credited_to": learned_action, "weight": round(weight, 4), "evaluated_at": now.isoformat()})
            await self.store.save(DECISIONS_INDEX, decision["decision_id"], {k: v for k, v in decision.items() if k != "_id"}, refresh=False)
            del active[source_ip]
            handled_before.add(source_ip)

        # 2. Decide for sources with recent detections and no running decision.
        lookback = now - timedelta(seconds=cfg["lookback_seconds"])
        recent: dict[str, list[dict[str, Any]]] = {}
        stored = await self._search("trapsig-detections", {"range": {"timestamp": {"gte": lookback.isoformat()}}}, size=2000, sort_field="timestamp")
        for detection in [*stored, *detections]:
            occurred = _parse(detection.get("timestamp") or detection.get("detected_at"))
            if detection.get("source_ip") and occurred and occurred >= lookback:
                recent.setdefault(detection["source_ip"], []).append(detection)
        posture_docs = {d["source_ip"]: d for d in await self._search(POSTURE_INDEX, size=1000, sort_field="updated_at") if d.get("source_ip")}
        for source_ip, items in sorted(recent.items()):
            if source_ip in active:
                continue
            types = sorted({str(d["type"]) for d in items if d.get("type")})
            stage = stage_for(types)
            surface = surface_for(s for d in items for s in (d.get("services") or []))
            context = context_key(stage, source_ip in handled_before, surface)
            seed = int(sha256(f"{source_ip}|{now.isoformat()}|{AGENT_VERSION}".encode()).hexdigest()[:12], 16)
            pick = choose(context, posteriors, cfg["allowed_actions"], random.Random(seed))
            enforced = pick["action"] if cfg["mode"] == "enforce" else "observe"
            previous = (posture_docs.get(source_ip) or {}).get("action", "observe")
            decision_id = "HRD-" + sha256(f"{source_ip}|{now.isoformat()}".encode()).hexdigest()[:16]
            decision = {
                "decision_id": decision_id,
                "source_ip": source_ip,
                "context": context,
                "stage": stage,
                "surface": surface,
                "returning": source_ip in handled_before,
                "detection_types": types,
                "action": pick["action"],
                "enforced_action": enforced,
                "effects": list(EFFECTS[enforced]),
                "previous_action": previous,
                "changed": previous != enforced,
                "mode": cfg["mode"],
                "chosen_by": "safety" if pick["safety"] and pick["chosen_by"] == "exploit" else pick["chosen_by"],
                "samples": pick["samples"],
                "means": pick["means"],
                "reason": pick["reason"] if cfg["mode"] == "enforce" else f"shadow mode: would apply {pick['action']} ({pick['reason']}); sensors keep observe",
                "decided_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=cfg["window_seconds"])).isoformat(),
                "status": "active",
                "agent_version": AGENT_VERSION,
            }
            await self.store.save(DECISIONS_INDEX, decision_id, decision, refresh=False)
            await self._write_posture(source_ip, enforced, decision_id, now)
            changed.append(decision)

        # 3. Release sources that went quiet.
        release_before = now - timedelta(seconds=cfg["release_after_seconds"])
        for source_ip, doc in posture_docs.items():
            if source_ip in recent or source_ip in {c["source_ip"] for c in changed} or doc.get("action", "observe") == "observe":
                continue
            updated = _parse(doc.get("updated_at"))
            if updated and updated < release_before:
                await self._write_posture(source_ip, "observe", None, now)
                changed.append({"source_ip": source_ip, "action": "observe", "previous_action": doc.get("action"), "released": True})

        await self.store.save(
            AGENT_INDEX,
            AGENT_DOC_ID,
            {**(await self._agent_meta()), "posteriors": posteriors, "updated_at": now.isoformat(), "config": cfg, "agent_version": AGENT_VERSION},
            refresh=False,
        )
        return changed

    async def _write_posture(self, source_ip: str, action: str, decision_id: str | None, now: datetime) -> None:
        document = {
            "source_ip": source_ip,
            "action": action,
            "actions": list(EFFECTS[action]),
            "level": LEVELS[action],
            "decision_id": decision_id,
            "updated_at": now.isoformat(),
            "entered_at": now.isoformat(),
        }
        await self.store.save(POSTURE_INDEX, "POS-" + sha256(source_ip.encode()).hexdigest()[:16], document, refresh=False)


def _legacy(context: str) -> tuple[str, bool, str]:
    parts = context.split("|")
    return parts[0], parts[-1] == "returning", "it"


def threshold_scale_for(level: str) -> float:
    """Detection sensitivity for a hardened source (learned heads only)."""
    from ..config import get_settings

    settings = get_settings()
    return {"elevated": settings.posture_elevated_threshold_scale, "locked": settings.posture_locked_threshold_scale}.get(level, 1.0)
