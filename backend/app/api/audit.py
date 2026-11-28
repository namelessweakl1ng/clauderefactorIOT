"""Read-only audit trail (admin role)."""

from typing import Any

from fastapi import APIRouter

from ..elastic import store
from ..security import AUDIT_INDEX

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def audit(limit: int = 200, outcome: str | None = None) -> list[dict[str, Any]]:
    query = {"term": {"outcome": outcome}} if outcome else None
    return await store.search(AUDIT_INDEX, query, size=max(1, min(limit, 1000)), sort_field="timestamp", missing_index_is_empty=True)
