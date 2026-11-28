"""Elasticsearch persistence for learned policy generations.

Policy weights live in the ``trapsig-policy`` index, never in a local file: a
backend restart, redeploy, or second replica must all converge on the same
learned state, and the time series of generations *is* the system's adaptation
history (Task E's dashboard reads it straight from here). Each training run writes
a new timestamped document; old generations are never overwritten.
"""

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from .policy import LinearPolicy

POLICY_INDEX = "trapsig-policy"


def _looks_like_policy(document: dict[str, Any]) -> bool:
    return isinstance(document.get("weights"), dict) and bool(document.get("weights"))


async def load_latest_policy(store: Any) -> LinearPolicy | None:
    """Return the most recent *active* stored policy, or ``None`` when there is none.

    Generations trained but not promoted by the evaluation gate are kept as
    history with ``active: false``; the live processor must ignore those. Policies
    with no ``active`` field (older generations, bootstrap) are treated as active
    for back-compat. Robust to simple injected stores and an absent index: any
    failure yields ``None`` so callers fall back to the deterministic bootstrap.
    """
    try:
        try:
            documents = await store.search(POLICY_INDEX, size=25, sort_field="trained_at", missing_index_is_empty=True)
        except TypeError:
            documents = await store.search(POLICY_INDEX, size=25, sort_field="trained_at")
    except Exception:
        return None
    from .features import FEATURE_NAMES

    # Generations trained on another feature schema cannot score current vectors
    # (different length/meaning); skip them instead of failing at inference.
    policies = [doc for doc in (documents or []) if _looks_like_policy(doc) and tuple(doc.get("feature_names", FEATURE_NAMES)) == FEATURE_NAMES]
    # Prefer the newest active generation; fall back to the newest of any status.
    for document in [doc for doc in policies if doc.get("active", True)] or policies:
        try:
            return LinearPolicy.from_document(document)
        except Exception:
            return None
    return None


async def save_policy(
    store: Any,
    policy: LinearPolicy,
    *,
    source: str,
    training_example_count: int,
    trained_at: str | None = None,
    active: bool = True,
    metrics: dict[str, Any] | None = None,
    feature_means: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist a new, timestamped policy generation and return the stored doc.

    ``active`` marks whether the live processor should adopt this generation; the
    promotion gate writes gated-out candidates with ``active=False`` so the
    training history stays complete without changing live behaviour.
    """
    trained_at = trained_at or datetime.now(timezone.utc).isoformat()
    document = policy.to_document(
        source=source,
        training_example_count=int(training_example_count),
        trained_at=trained_at,
        active=bool(active),
        evaluation=metrics or {},
        feature_means=feature_means or {},
        trapsig={"schema_version": "1"},
        **(extra or {}),
    )
    # Deterministic, collision-resistant id from content + timestamp keeps writes
    # idempotent on retry without ever clobbering a different generation.
    fingerprint = sha256(f"{policy.policy_version}|{trained_at}|{source}".encode()).hexdigest()[:16]
    document_id = f"POL-{fingerprint}"
    await store.save(POLICY_INDEX, document_id, document)
    return {**document, "_id": document_id}
