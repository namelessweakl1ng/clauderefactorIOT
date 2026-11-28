"""Bounded single-target service probe (connect-scan of known TRAPSIG ports).

This confirms which of the *one validated target's* known services are up. It is
reconnaissance of one host's known ports -- never a range scan -- so it stays
inside the existing safety principle.

    python -m attacks.realistic.service_probe --target 192.168.50.10
"""

import argparse
import random
import socket

from attacks.runner.run import PORTS

from .common import build_summary, jitter_sleep, now_iso, resolve_target, step

EXPECTED_DETECTION = "RECONNAISSANCE"


def _probe(target: str, service: str, port: int, number: int) -> dict:
    started = now_iso()
    try:
        with socket.create_connection((target, port), timeout=2):
            return step(number, service, "completed", started, f"{service}:{port} open")
    except OSError as exc:
        return step(number, service, "rejected", started, f"{service}:{port} closed ({exc})")


def run(target: str, *, services=None, jitter: float = 0.2, seed: int = 7) -> dict:
    target = resolve_target(target)
    rng = random.Random(seed)
    # One entry per known service port; de-duplicate ports that alias (camera/http).
    service_ports = {service: PORTS[service] for service in (services or PORTS)}
    seen: set[int] = set()
    start = now_iso()
    steps = []
    number = 0
    for service, port in service_ports.items():
        if port in seen:
            continue
        seen.add(port)
        number += 1
        jitter_sleep(0, jitter, rng)
        steps.append(_probe(target, service, port, number))
    return build_summary(
        technique="service-probe",
        target=target,
        expected_detection=EXPECTED_DETECTION,
        start_time=start,
        steps=steps,
        extra={"ports_probed": sorted(seen)},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--services", nargs="+", default=None, choices=sorted(PORTS))
    parser.add_argument("--jitter", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    import json

    print(json.dumps(run(args.target, services=args.services, jitter=args.jitter, seed=args.seed), indent=2))


if __name__ == "__main__":
    main()
