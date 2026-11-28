"""API authentication, role-based authorization and audit logging.

Keys
----
``API_KEYS`` holds comma-separated ``role:key`` pairs, e.g.
``viewer:abc,analyst:def,admin:ghi,sensor:jkl``. The legacy single ``API_KEY``
still works and maps to ``admin``. With no keys configured the API stays open
(isolated-lab default) and every caller is treated as ``admin``; the audit trail
still records actions as ``anonymous``.

Roles
-----
``viewer < analyst < admin`` form a hierarchy. ``sensor`` is separate and may
only send heartbeats and read posture -- a compromised Pi key cannot read
telemetry or change detection.

Policy
------
One explicit table (:data:`POLICY`) maps (method, path pattern) to the minimum
role, so the whole authorization surface is reviewable in one place. Anything not
listed falls back to: reads need ``viewer``, writes need ``analyst``.

Keys are compared with :func:`hmac.compare_digest`. Keys are read at request
time so they can be rotated without restarting the API.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

LOGGER = logging.getLogger(__name__)
AUDIT_INDEX = "trapsig-audit"
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
ROLES = (*ROLE_RANK, "sensor")
EXEMPT_PREFIXES = ("/health", "/metrics", "/docs", "/redoc", "/openapi.json")

# (methods, compiled path regex, allowed roles). First match wins.
POLICY: list[tuple[frozenset[str], re.Pattern[str], frozenset[str]]] = [
    (frozenset({"POST"}), re.compile(r"^/sensors/heartbeat$"), frozenset({"sensor", "admin"})),
    (frozenset({"GET"}), re.compile(r"^/adaptation/posture$"), frozenset({"sensor", "viewer", "analyst", "admin"})),
    (frozenset({"GET"}), re.compile(r"^/personas/[^/]+/effective$"), frozenset({"sensor", "viewer", "analyst", "admin"})),
    (frozenset({"GET"}), re.compile(r"^/fleet/[^/]+/assignment$"), frozenset({"sensor", "viewer", "analyst", "admin"})),
    (frozenset({"PUT", "POST", "DELETE"}), re.compile(r"^/fleet(/.*)?$"), frozenset({"admin"})),
    (frozenset({"POST"}), re.compile(r"^/honeypots/[^/]+/(start|stop|restart)$"), frozenset({"admin"})),
    (frozenset({"POST", "PUT", "DELETE"}), re.compile(r"^/detection/rules/[^/]+/state$"), frozenset({"admin"})),
    (frozenset({"POST", "PUT", "DELETE"}), re.compile(r"^/(personas|deception)(/.*)?$"), frozenset({"admin"})),
    (frozenset({"GET"}), re.compile(r"^/audit(/.*)?$"), frozenset({"admin"})),
]


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    authenticated: bool

    def at_least(self, role: str) -> bool:
        if self.role == "sensor" or role == "sensor":
            return self.role == role
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[role]


def configured_keys() -> list[tuple[str, str]]:
    """Return ``[(role, key), ...]`` from the environment (request-time read)."""
    pairs: list[tuple[str, str]] = []
    for item in (os.getenv("API_KEYS") or "").split(","):
        item = item.strip()
        if not item:
            continue
        role, separator, key = item.partition(":")
        role = role.strip().lower()
        if separator and key.strip() and role in ROLES:
            pairs.append((role, key.strip()))
        else:
            LOGGER.warning("ignoring malformed API_KEYS entry for role %r", role)
    legacy = os.getenv("API_KEY", "")
    if legacy:
        pairs.append(("admin", legacy))
    return pairs


def authenticate(provided: str | None) -> Principal | None:
    keys = configured_keys()
    if not keys:
        return Principal("anonymous", "admin", authenticated=False)
    if not provided:
        return None
    match: Principal | None = None
    for index, (role, key) in enumerate(keys):
        # Compare against every key (no early exit) to keep timing uniform.
        if hmac.compare_digest(provided.encode(), key.encode()) and match is None:
            match = Principal(f"{role}-key-{index + 1}", role, authenticated=True)
    return match


def allowed_roles(method: str, path: str) -> frozenset[str]:
    for methods, pattern, roles in POLICY:
        if method in methods and pattern.match(path):
            return roles
    if method in {"GET", "HEAD", "OPTIONS"}:
        return frozenset({"viewer", "analyst", "admin"})
    return frozenset({"analyst", "admin"})


def authorize(principal: Principal, method: str, path: str) -> bool:
    if not principal.authenticated:
        return True  # open lab mode
    roles = allowed_roles(method, path)
    if principal.role in roles:
        return True
    # Hierarchy: a higher human role satisfies any lower human requirement.
    human = [role for role in roles if role in ROLE_RANK]
    return principal.role in ROLE_RANK and any(principal.at_least(role) for role in human)


async def write_audit(store: Any, record: dict[str, Any]) -> None:
    """Append one audit record; failures are logged, never raised (best effort)."""
    try:
        await store.save(AUDIT_INDEX, record["audit_id"], record, refresh=False)
    except Exception:  # pragma: no cover - depends on ES availability
        LOGGER.warning("audit write failed for %s %s", record.get("method"), record.get("path"), exc_info=True)


def audit_record(request: Request, principal: Principal | None, status: int, outcome: str) -> dict[str, Any]:
    return {
        "audit_id": "AUD-" + uuid.uuid4().hex[:16],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "principal": principal.name if principal else None,
        "role": principal.role if principal else None,
        "authenticated": bool(principal and principal.authenticated),
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query or None,
        "status": status,
        "outcome": outcome,
        "client_ip": request.client.host if request.client else None,
        "request_id": request.headers.get("x-request-id"),
    }


def should_audit(method: str, status: int) -> bool:
    return method not in {"GET", "HEAD", "OPTIONS"} or status in {401, 403}


async def security_middleware(request: Request, call_next, store: Any):
    path, method = request.url.path, request.method
    if method == "OPTIONS" or any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES):
        return await call_next(request)
    principal = authenticate(request.headers.get("x-api-key"))
    if principal is None:
        await write_audit(store, audit_record(request, None, 401, "unauthenticated"))
        return JSONResponse({"detail": "invalid or missing API key"}, status_code=401)
    if not authorize(principal, method, path):
        await write_audit(store, audit_record(request, principal, 403, "forbidden"))
        return JSONResponse({"detail": f"role '{principal.role}' may not {method} {path}"}, status_code=403)
    request.state.principal = principal
    response = await call_next(request)
    if should_audit(method, response.status_code):
        await write_audit(store, audit_record(request, principal, response.status_code, "ok" if response.status_code < 400 else "error"))
    return response


def principal_of(request: Request) -> Principal:
    return getattr(request.state, "principal", None) or Principal("anonymous", "admin", authenticated=False)
