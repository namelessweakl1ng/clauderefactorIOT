"""Persisted rule activation overrides (``trapsig-rule-state``).

Rule *content* is versioned in Git (and content-hashed); only the operator's
enable/disable decision is runtime state. Every change is also appended to the
audit index by the API layer. The processor reloads overrides each cycle so all
replicas converge; any failure keeps the previous overrides (fail-static) rather
than silently re-enabling a rule an operator turned off.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

RULE_STATE_INDEX = "trapsig-rule-state"


async def load_rule_states(store: Any, previous: dict[str, bool] | None = None) -> dict[str, bool]:
    try:
        documents = await store.search(RULE_STATE_INDEX, size=1000, sort_field="updated_at", missing_index_is_empty=True)
    except TypeError:
        try:
            documents = await store.search(RULE_STATE_INDEX, size=1000, sort_field="updated_at")
        except Exception:
            return dict(previous or {})
    except Exception:
        return dict(previous or {})
    states: dict[str, bool] = {}
    for document in documents or []:
        rule_id = document.get("rule_id")
        if rule_id and isinstance(document.get("enabled"), bool):
            states[str(rule_id)] = document["enabled"]
    return states


async def save_rule_state(store: Any, rule_id: str, enabled: bool, *, actor: str | None, reason: str | None = None) -> dict[str, Any]:
    document = {
        "rule_id": rule_id,
        "enabled": bool(enabled),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_by": actor,
        "reason": reason,
    }
    await store.save(RULE_STATE_INDEX, rule_id, document)
    return document
