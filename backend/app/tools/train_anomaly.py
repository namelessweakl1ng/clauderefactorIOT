"""Train and store an isolation-forest anomaly model from observed sessions.

By default fits on sessions of completed *control* experiments (the benign lab
baseline, classic novelty detection). ``--all-sessions`` fits on every
reconstructed session in the lookback window instead ("unlike what this fleet
usually sees"). There is no synthetic fallback: novelty relative to invented data
would be meaningless, so with too little data the tool refuses.

    python -m backend.app.tools.train_anomaly [--all-sessions] [--lookback-days 14] [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import get_settings
from ..elastic import store as default_store
from ..services.detection.anomaly import IsolationForest, save_anomaly_model
from ..services.ml.features import feature_vector
from ..services.sessionizer import reconstruct_sessions
from ..services.telemetry import is_internal_event
from .train_policy import _completed_experiments, _sessions_for


async def collect_vectors(store: Any, *, all_sessions: bool, lookback_days: int) -> tuple[list[list[float]], str]:
    timeout = get_settings().session_timeout_seconds
    if not all_sessions:
        vectors = []
        for experiment in await _completed_experiments(store):
            if experiment.get("trial_kind") == "control" and experiment.get("result") not in {None, "INCONCLUSIVE"}:
                vectors.extend(feature_vector(s) for s in await _sessions_for(store, experiment, timeout))
        return vectors, "control-experiments"
    since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
    events = await store.search_all("trapsig-events-*", {"range": {"@timestamp": {"gte": since}}}, sort=[{"@timestamp": "asc"}], missing_index_is_empty=True)
    sessions = reconstruct_sessions([e for e in events if not is_internal_event(e)], timeout)
    return [feature_vector(s) for s in sessions], f"all-sessions-{lookback_days}d"


async def run(store: Any, *, all_sessions: bool, lookback_days: int, contamination: float, seed: int, dry_run: bool) -> dict[str, Any]:
    vectors, source = await collect_vectors(store, all_sessions=all_sessions, lookback_days=lookback_days)
    if len(vectors) < 8:
        return {"trained": False, "reason": f"only {len(vectors)} sessions from {source}; need ≥ 8", "source": source}
    model = IsolationForest.fit(vectors, contamination=contamination, seed=seed)
    summary = {"trained": True, "source": source, "sessions": len(vectors), "model_version": model.model_version, "threshold": model.threshold}
    if not dry_run:
        stored = await save_anomaly_model(store, model, source=source, extra={"contamination": contamination})
        summary["document_id"] = stored["_id"]
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all-sessions", action="store_true")
    parser.add_argument("--lookback-days", type=int, default=14)
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=20261126)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    async def go() -> None:
        try:
            result = await run(
                default_store,
                all_sessions=args.all_sessions,
                lookback_days=args.lookback_days,
                contamination=args.contamination,
                seed=args.seed,
                dry_run=args.dry_run,
            )
        finally:
            await default_store.close()
        for key, value in result.items():
            print(f"{key}: {value}")

    asyncio.run(go())


if __name__ == "__main__":
    main()
