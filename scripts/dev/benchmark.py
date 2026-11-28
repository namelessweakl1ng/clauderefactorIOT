#!/usr/bin/env python3
"""In-process performance benchmark for the TRAPSIG detection pipeline.

Retires the "physical performance NOT MEASURED" caveat with reproducible numbers
for the CPU-bound stages that run on the laptop (and would run on the Pi): feature
extraction throughput, per-session detection latency, bootstrap + batch training
time, and a full processor cycle over a synthetic event corpus. It needs no
Elasticsearch, no Docker and no hardware wiring, so it runs anywhere (Linux or
Windows); run it ON the Pi/laptop to get that machine's numbers.

    python scripts/dev/benchmark.py
    python scripts/dev/benchmark.py --sessions 500 --json

Resource usage (CPU%, RSS) on the real Pi is still best captured with the OS
tools noted in docs/research/EVALUATION.md while this harness drives load; this measures
the algorithmic cost, which is the part that was previously unquantified.
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.services.detector import detect  # noqa: E402
from backend.app.services.ml.bootstrap import DETECTION_TYPES, bootstrap_policy, build_training_examples  # noqa: E402
from backend.app.services.ml.features import feature_vector  # noqa: E402
from backend.app.services.ml.training import train  # noqa: E402
from backend.app.services.processor import EventProcessor  # noqa: E402


def _session(index: int) -> dict:
    events = [
        {
            "event": {"id": f"e{index}-{i}", "category": "authentication", "outcome": "failure"},
            "network": {"protocol": "ssh"},
            "service": {"name": "cowrie"},
            "authentication": {"username": "admin", "password": "admin"},
        }
        for i in range(8)
    ]
    return {
        "session_id": f"SES-{index}",
        "source_ip": f"192.168.50.{20 + (index % 200)}",
        "end_time": "2026-01-01T00:00:00Z",
        "event_ids": [e["event"]["id"] for e in events],
        "events": events,
        "services_touched": ["cowrie"],
        "commands": [],
        "urls": [],
    }


def _timed(label: str, func, *, repeat: int = 1) -> dict:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        func()
        samples.append((time.perf_counter() - start) * 1000.0)
    return {"stage": label, "runs": repeat, "mean_ms": statistics.fmean(samples), "min_ms": min(samples), "max_ms": max(samples)}


def run(sessions: int) -> dict:
    results = []

    # Cold bootstrap training (first call; cached afterwards).
    bootstrap_policy.cache_clear()
    results.append(_timed("bootstrap_train", bootstrap_policy))
    policy = bootstrap_policy()

    sample_sessions = [_session(i) for i in range(sessions)]

    def extract_all():
        for session in sample_sessions:
            feature_vector(session)

    results.append(_timed("feature_extract_batch", extract_all))
    results[-1]["throughput_per_sec"] = sessions / (results[-1]["mean_ms"] / 1000.0) if results[-1]["mean_ms"] else None

    def detect_all():
        for session in sample_sessions:
            detect(session, policy=policy)

    results.append(_timed("detect_batch", detect_all))
    results[-1]["per_session_ms"] = results[-1]["mean_ms"] / sessions if sessions else None

    examples = build_training_examples()

    def batch_train():
        train(examples, DETECTION_TYPES, epochs=50, warm_start=policy, policy_version="bench")

    results.append(_timed("batch_train_50_epochs", batch_train))

    # Full processor cycle over a synthetic event corpus.
    class Store:
        def __init__(self, events):
            self.events = events
            self.documents = {}

        async def search(self, index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
            return self.events if index == "trapsig-events-*" else []

        async def save(self, index, document_id, document, *, refresh="wait_for"):
            self.documents[(index, document_id)] = document
            return document

        async def refresh(self, *indices):
            return None

    raw_events = []
    for index in range(sessions):
        for i in range(8):
            raw_events.append(
                {
                    "@timestamp": f"2026-01-01T00:{index % 60:02d}:{i:02d}Z",
                    "event": {"id": f"r{index}-{i}", "category": "authentication", "outcome": "failure"},
                    "source": {"ip": f"192.168.50.{20 + (index % 200)}"},
                    "service": {"name": "cowrie"},
                    "honeypot": {"id": "cowrie-01"},
                    "network": {"protocol": "ssh"},
                    "authentication": {"username": "admin", "password": "admin"},
                }
            )
    import asyncio

    processor = EventProcessor(Store(raw_events))
    results.append(_timed("processor_cycle", lambda: asyncio.run(processor.process_once())))

    return {"sessions": sessions, "event_count": len(raw_events), "detection_types": len(DETECTION_TYPES), "stages": results}


def _format(report: dict) -> str:
    lines = [f"TRAPSIG benchmark  (sessions={report['sessions']}, events={report['event_count']})", ""]
    lines.append(f"{'stage':<26}{'mean_ms':>12}{'min_ms':>10}{'max_ms':>10}  notes")
    for stage in report["stages"]:
        note = ""
        if "throughput_per_sec" in stage and stage["throughput_per_sec"]:
            note = f"{stage['throughput_per_sec']:.0f} sessions/s"
        elif "per_session_ms" in stage and stage["per_session_ms"]:
            note = f"{stage['per_session_ms']:.3f} ms/session"
        lines.append(f"{stage['stage']:<26}{stage['mean_ms']:>12.2f}{stage['min_ms']:>10.2f}{stage['max_ms']:>10.2f}  {note}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", type=int, default=200, help="synthetic session/event volume (default 200)")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args()
    report = run(args.sessions)
    print(json.dumps(report, indent=2) if args.json else _format(report))


if __name__ == "__main__":
    main()
