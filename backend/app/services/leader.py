"""Single-writer leader election so only one processor materializes derived data.

``EventProcessor`` runs in every backend replica's lifespan and rebuilds *all*
sessions each cycle. If two replicas run it at once they double-write sessions,
detections and posture. This lease makes exactly one replica the active writer at
a time, using an Elasticsearch document with optimistic concurrency
(``if_seq_no``/``if_primary_term`` compare-and-set) and a short TTL so a crashed
leader's lease is taken over automatically.

It is deliberately fail-open for anything that is not a real ES-backed store: when
the store exposes no ``client`` (the simple in-memory stores used by tests and by
callers that just want one instance), :meth:`is_leader` returns ``True``. Leader
election only gates the background ``run()`` loop; explicit, user-triggered
``process_once()`` calls (e.g. finishing an experiment) are never gated.
"""

import os
import socket
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from elasticsearch import ConflictError, NotFoundError
except Exception:  # pragma: no cover - elasticsearch always present in backend
    ConflictError = NotFoundError = Exception  # type: ignore[assignment,misc]

LOCKS_INDEX = "trapsig-locks"
PROCESSOR_LOCK = "processor"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _identity() -> str:
    # Stable-ish per-process identity: hostname + pid + a random suffix.
    return f"{socket.gethostname()}-{os.getpid()}-{uuid4().hex[:8]}"


class LeaderElector:
    """Best-effort, fail-open ES lease for the single-writer processor."""

    def __init__(self, store: Any, *, lock_name: str = PROCESSOR_LOCK, ttl_seconds: int = 30) -> None:
        self.store = store
        self.lock_name = lock_name
        self.ttl_seconds = ttl_seconds
        self.owner = _identity()
        self._client = getattr(store, "client", None)

    @property
    def enabled(self) -> bool:
        return self._client is not None

    async def is_leader(self) -> bool:
        """Acquire or renew the lease; return whether this process may write.

        Fail-open: if the store has no ES client, or any transient error occurs
        while contending, default to being the leader rather than stalling the
        pipeline. Double-writes are idempotent (content-derived IDs) so a brief
        overlap during ES trouble is safe; a permanent split-brain is what the
        lease prevents in normal operation.
        """
        if not self.enabled:
            return True
        try:
            return await self._acquire_or_renew()
        except ConflictError:
            # Another replica won this round; it is the leader.
            return False
        except Exception:
            # Transient ES issue: fail open (idempotent writes keep this safe).
            return True

    async def _acquire_or_renew(self) -> bool:
        assert self._client is not None  # guarded by is_leader()/enabled
        now = _now()
        expires = now.timestamp() + self.ttl_seconds
        document = {"owner": self.owner, "acquired_at": now.isoformat(), "expires_at": expires}
        try:
            current = await self._client.get(index=LOCKS_INDEX, id=self.lock_name)
        except NotFoundError:
            current = None
        except Exception:
            # Index may not exist yet; attempt a create below.
            current = None

        if current is None:
            try:
                await self._client.index(index=LOCKS_INDEX, id=self.lock_name, document=document, op_type="create", refresh="wait_for")
                return True
            except ConflictError:
                return False

        source = current.get("_source", {})
        held_by_me = source.get("owner") == self.owner
        expired = float(source.get("expires_at", 0)) <= now.timestamp()
        if not (held_by_me or expired):
            return False
        # Compare-and-set against the exact version we read, so two contenders
        # cannot both take an expired lease.
        await self._client.index(
            index=LOCKS_INDEX,
            id=self.lock_name,
            document=document,
            if_seq_no=current["_seq_no"],
            if_primary_term=current["_primary_term"],
            refresh="wait_for",
        )
        return True

    async def release(self) -> None:
        """Best-effort release on graceful shutdown so failover is immediate."""
        if self._client is None:
            return
        try:
            current = await self._client.get(index=LOCKS_INDEX, id=self.lock_name)
            if current.get("_source", {}).get("owner") != self.owner:
                return
            await self._client.delete(
                index=LOCKS_INDEX,
                id=self.lock_name,
                if_seq_no=current["_seq_no"],
                if_primary_term=current["_primary_term"],
                refresh="wait_for",
            )
        except Exception:
            # A lease we fail to release simply expires via its TTL.
            return
