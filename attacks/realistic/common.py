"""Shared helpers for the realistic attack toolkit: safety, results, wordlists.

Ground-truth mapping for training
---------------------------------
Each script declares an ``expected_detection`` in its summary -- the detection
type its traffic is designed to provoke (e.g. credential stuffing ->
``BRUTE_FORCE``). That is the same ground-truth contract the YAML scenarios carry
via ``expected_detection``. Two ways these feed Task A's batch retraining:

* Run the script while a TRAPSIG experiment is *running* against the same target;
  the experiment's correlation links the generated sessions and the detector's
  output, and ``train_policy.py`` turns the completed experiment into labeled
  examples -- identical to how YAML scenarios are used.
* Or treat the emitted summary's ``expected_detection`` as the label directly for
  offline analysis of the ``attacks/runs/*.json`` files.

Nothing here decides what fires; the declared label is the *attacker's intent*,
which is exactly the ground truth training needs.
"""

import json
import os
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from attacks.runner.run import PORTS
from attacks.runner.safety import validate_target

try:  # Shared source of truth for "known weak" with the detector's feature input.
    from backend.app.services.ml.known_weak_credentials import KNOWN_WEAK_CREDENTIALS
except Exception:  # pragma: no cover - backend not importable in some runner envs
    KNOWN_WEAK_CREDENTIALS = frozenset({("admin", "admin"), ("root", "root"), ("pi", "raspberry")})

_CREDENTIALS_DIR = Path(__file__).resolve().parents[1] / "credentials"
_RUNS_DIR = Path(__file__).resolve().parents[1] / "runs"

USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/121.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Wget/1.21.4",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) Version/17.1 Mobile Safari/604.1",
)


def resolve_target(target: str | None) -> str:
    """Validate the single explicit target against LAB_SUBNET (raises on misuse)."""
    return validate_target(target, os.environ.get("LAB_SUBNET", ""))


def known_weak_pairs() -> list[tuple[str, str]]:
    """The shared known-weak (username, password) pairs, deterministically ordered."""
    return sorted(KNOWN_WEAK_CREDENTIALS)


def load_wordlist(name: str) -> list[str]:
    path = _CREDENTIALS_DIR / name
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def credential_product(limit: int | None = None, seed: int = 1337) -> list[tuple[str, str]]:
    """Bounded username x password product from the shared wordlists plus known pairs."""
    users = load_wordlist("users.txt") or [u for u, _ in known_weak_pairs()]
    passwords = load_wordlist("passwords.txt") or [p for _, p in known_weak_pairs()]
    pairs = list(dict.fromkeys(known_weak_pairs() + [(u, p) for u in users for p in passwords]))
    rng = random.Random(seed)
    rng.shuffle(pairs)
    return pairs[:limit] if limit else pairs


def jitter_sleep(low: float, high: float, rng: random.Random) -> None:
    if high > 0:
        time.sleep(rng.uniform(max(0.0, low), high))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def step(number: int, service: str, status: str, started_at: str, detail: str | None = None) -> dict[str, Any]:
    item = {"step": number, "service": service, "started_at": started_at, "ended_at": now_iso(), "status": status}
    if detail:
        item["detail"] = detail[:200]
    return item


def build_summary(
    *,
    technique: str,
    target: str,
    expected_detection: str,
    start_time: str,
    steps: list[dict[str, Any]],
    source: str = "controlled-attacker",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a runner-compatible result summary and persist it under runs/."""
    failures = sum(s["status"] == "failed" for s in steps)
    overall = "completed" if failures == 0 else ("failed" if failures == len(steps) else "partial")
    summary = {
        "run_id": "RUN-" + uuid.uuid4().hex[:12],
        "technique": technique,
        "scenario_id": f"realistic-{technique}",
        "target": target,
        "source": source,
        "expected_detection": expected_detection,
        "start_time": start_time,
        "end_time": now_iso(),
        "overall_status": overall,
        "step_count": len(steps),
        "steps": steps,
        **(extra or {}),
    }
    _RUNS_DIR.mkdir(exist_ok=True)
    (_RUNS_DIR / f"{summary['run_id']}.json").write_text(json.dumps(summary, indent=2))
    return summary


def run_pool(tasks: list[Callable[[], dict[str, Any]]], workers: int) -> list[dict[str, Any]]:
    """Execute per-attempt callables concurrently, preserving submission order."""
    from concurrent.futures import ThreadPoolExecutor

    if workers <= 1:
        return [task() for task in tasks]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda task: task(), tasks))


def port_for(service: str) -> int:
    return PORTS[service]
