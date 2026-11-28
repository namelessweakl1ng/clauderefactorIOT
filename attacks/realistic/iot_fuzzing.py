"""IoT protocol fuzzing against the line-oriented IoT TCP service.

Sends malformed / boundary payloads that respect the service's documented bounded
single-line protocol (one newline-terminated command under its size cap). The
point is varied/garbled input, not a stability test -- it does not try to crash
the container.

    python -m attacks.realistic.iot_fuzzing --target 192.168.50.10 --count 15
"""

import argparse
import random
import socket

from .common import build_summary, jitter_sleep, now_iso, port_for, resolve_target, step

EXPECTED_DETECTION = "RECONNAISSANCE"

_BASE_COMMANDS = ("STATUS", "INFO", "ID", "GET", "SET", "PING", "VERSION", "HELP", "RESET", "DIAG")


def _payloads(rng: random.Random, count: int) -> list[bytes]:
    payloads: list[bytes] = []
    for _ in range(count):
        choice = rng.random()
        if choice < 0.3:
            payloads.append((rng.choice(_BASE_COMMANDS) + " " + "".join(rng.choice("ABCDEF0123456789") for _ in range(rng.randint(1, 12)))).encode())
        elif choice < 0.5:
            # Boundary: a long but still bounded line (under the 1024-byte cap).
            payloads.append((rng.choice(_BASE_COMMANDS) + " " + "A" * rng.randint(200, 900)).encode())
        elif choice < 0.7:
            # Non-ASCII / control bytes within one line.
            payloads.append(bytes(rng.randint(1, 254) for _ in range(rng.randint(4, 40))).replace(b"\n", b" "))
        elif choice < 0.85:
            payloads.append(rng.choice(_BASE_COMMANDS).encode() + b"\x00\x01\x02")
        else:
            payloads.append(rng.choice(_BASE_COMMANDS).lower().encode())
    return payloads


def _send(target: str, payload: bytes, number: int) -> dict:
    started = now_iso()
    try:
        with socket.create_connection((target, port_for("iot")), timeout=2) as connection:
            connection.sendall(payload + b"\n")
            connection.recv(256)
        return step(number, "iot", "completed", started, payload[:40].hex())
    except Exception as exc:
        return step(number, "iot", "failed", started, str(exc))


def run(target: str, *, count: int = 12, jitter: float = 0.2, seed: int = 55) -> dict:
    target = resolve_target(target)
    rng = random.Random(seed)
    start = now_iso()
    steps = []
    for number, payload in enumerate(_payloads(rng, count), 1):
        jitter_sleep(0, jitter, rng)
        steps.append(_send(target, payload, number))
    return build_summary(
        technique="iot-fuzzing",
        target=target,
        expected_detection=EXPECTED_DETECTION,
        start_time=start,
        steps=steps,
        extra={"payloads": count},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--jitter", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=55)
    args = parser.parse_args()
    import json

    print(json.dumps(run(args.target, count=args.count, jitter=args.jitter, seed=args.seed), indent=2))


if __name__ == "__main__":
    main()
