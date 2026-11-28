"""Sensor-side posture cache: a tiny, fail-open background poller.

The honeypot personas are synchronous per-connection handlers running in
read-only containers with strict pids/mem/cpu limits. This module lets them vary
their behaviour for a suspicious source IP **without** adding any blocking network
call to the request hot path and **without** writing to the filesystem:

* A single daemon thread polls the backend's ``GET /adaptation/posture`` every few
  seconds (stdlib ``urllib`` only -- no new pip dependency) with a short timeout.
* It caches ``{ip: level}`` in memory behind a lock.
* Personas call :func:`posture_for` -- a pure dict lookup, no I/O.

**Fail open is the whole point:** on any error, timeout, or unreachable backend we
keep the last-known-good cache (or ``normal`` if we have none). A network hiccup
must never block a connection or escalate behaviour; the honeypot degrades to
ordinary "normal" posture, never to a "locked" state it cannot justify.

The backend address comes from an env var (set to the Tailscale address once Task
D is in place), so this works identically whether the Pi is on home Wi-Fi or a
phone hotspot.
"""

import json
import os
import random
import threading
import time
import urllib.request

NORMAL = "normal"
ELEVATED = "elevated"
LOCKED = "locked"

_DEFAULT_INTERVAL = 5.0
_DEFAULT_TIMEOUT = 2.0

# Bounded artificial delay for a suspicious source: enough to look like a loaded
# device, not enough to be its own DoS vector. KNOWN TRADE-OFF (documented in
# docs/reference/ARCHITECTURE.md): under heavy concurrent connections from a locked IP this
# per-connection delay is itself a mild self-inflicted DoS risk given the
# container's pids_limit: 64. Acceptable at lab scale; a per-source connection cap
# is a Phase 2 item rather than something engineered now.
_MAX_DELAY_SECONDS = 0.5


def connection_delay(level: str, *, rng: random.Random | None = None) -> float:
    """Sleep a bounded, jittered delay for elevated/locked sources; return it.

    No-op for normal posture, so honeypot behaviour and the persona unit tests
    are unchanged when no posture applies.
    """
    if level not in (ELEVATED, LOCKED):
        return 0.0
    picker = rng or random
    delay = picker.uniform(0.15, _MAX_DELAY_SECONDS)
    time.sleep(delay)
    return delay

KNOWN_EFFECTS = frozenset({"tarpit", "deny_auth", "read_only", "drop_udp"})
_LEVEL_EFFECTS = {LOCKED: frozenset({"tarpit", "deny_auth"}), ELEVATED: frozenset({"tarpit"})}

KNOWN_EFFECTS = frozenset({"tarpit", "deny_auth", "read_only", "drop_udp"})
_LEVEL_EFFECTS = {LOCKED: frozenset({"tarpit", "deny_auth"}), ELEVATED: frozenset({"tarpit"})}

_lock = threading.Lock()
_levels: dict[str, str] = {}
_hardening: dict[str, tuple[frozenset[str], str | None]] = {}
_hardening: dict[str, tuple[frozenset[str], str | None]] = {}
_started = False


def posture_for(ip: str) -> str:
    """Return the cached posture level for *ip* (``normal`` when unknown)."""
    with _lock:
        return _levels.get(ip, NORMAL)


def hardening_for(ip: str) -> tuple[frozenset[str], str | None]:
    """Return (effects, decision_id) the backend's RL agent assigned to *ip*.

    Pure dict lookup. Unknown effect names are ignored, so a newer backend can
    never make an older sensor do something it does not implement.
    """
    with _lock:
        return _hardening.get(ip, (frozenset(), None))


def _apply(entries: dict) -> None:
    """Install a new cache: ``{ip: level}`` or ``{ip: {level, actions, decision_id}}``."""
    global _levels, _hardening
    levels: dict[str, str] = {}
    hardening: dict[str, tuple[frozenset[str], str | None]] = {}
    for ip, value in entries.items():
        if isinstance(value, dict):
            level = value.get("level") or NORMAL
            effects = frozenset(value.get("actions") or ()) & KNOWN_EFFECTS
            decision = value.get("decision_id")
        else:
            level, effects, decision = value, _LEVEL_EFFECTS.get(value, frozenset()), None
        levels[ip] = level
        if effects:
            hardening[ip] = (effects, decision)
    with _lock:
        _levels, _hardening = levels, hardening


def _fetch(url: str, timeout: float) -> dict:
    headers = {"User-Agent": "trapsig-sensor-posture/1"}
    # With API auth enabled the backend requires a key; the sensor role may read
    # posture (and nothing else). Without it every poll 401s and fails open.
    if os.getenv("SENSOR_API_KEY"):
        headers["X-API-Key"] = os.environ["SENSOR_API_KEY"]
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed lab backend URL
        payload = json.loads(response.read(1_000_000).decode("utf-8"))
    entries: dict = {}
    # Posture documents: {source_ip, level, actions, decision_id}.
    for item in payload if isinstance(payload, list) else []:
        ip = item.get("source_ip")
        if ip and item.get("level"):
            actions = [a for a in item.get("actions") or [] if isinstance(a, str)]
            entries[ip] = {"level": item["level"], "actions": actions, "decision_id": item.get("decision_id")}
    return entries


def _poll_loop(url: str, interval: float, timeout: float, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            _apply(_fetch(url, timeout))
        except Exception:
            # Fail open: keep the last-known-good cache; never raise, never block.
            pass
        stop.wait(interval)


def start_posture_poller(stop: threading.Event | None = None) -> threading.Event:
    """Start the background poller once; returns its stop event.

    No-op (returns immediately) when no backend posture URL is configured, so a
    sensor with the feature disabled simply behaves as always-normal.
    """
    global _started
    stop = stop or threading.Event()
    url = os.getenv("POSTURE_URL") or (
        f"{os.getenv('BACKEND_URL').rstrip('/')}/adaptation/posture" if os.getenv("BACKEND_URL") else ""
    )
    if _started or not url:
        return stop
    interval = float(os.getenv("POSTURE_POLL_INTERVAL", _DEFAULT_INTERVAL))
    timeout = float(os.getenv("POSTURE_POLL_TIMEOUT", _DEFAULT_TIMEOUT))
    thread = threading.Thread(target=_poll_loop, args=(url, interval, timeout, stop), name="posture-poller", daemon=True)
    thread.start()
    _started = True
    return stop
