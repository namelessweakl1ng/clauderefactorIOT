"""MQTT probing / light bounded flood against the lab's own MQTT decoy.

Varies topic names, QoS, and client IDs across a bounded burst of
connect/subscribe/publish traffic. Non-adaptive and bounded: the burst size is
capped and targets only the single validated MQTT decoy.

    python -m attacks.realistic.mqtt_probing --target 192.168.50.10 --burst 20
"""

import argparse
import random
import socket

from attacks.runner.run import _mqtt_remaining_length, _mqtt_string

from .common import build_summary, jitter_sleep, now_iso, port_for, resolve_target, step

EXPECTED_DETECTION = "MQTT_PROBING"

_TOPICS = ("#", "$SYS/#", "home/+/status", "devices/camera/stream", "sensors/temp", "cmd/reboot", "config/set", "+/+/+")


def _connect(client_id: str) -> bytes:
    body = b"\x00\x04MQTT\x04\x02\x00\x0a" + _mqtt_string(client_id)
    return b"\x10" + _mqtt_remaining_length(len(body)) + body


def _subscribe(topic: str, qos: int, packet_id: int) -> bytes:
    body = packet_id.to_bytes(2, "big") + _mqtt_string(topic) + bytes([qos & 0x03])
    return b"\x82" + _mqtt_remaining_length(len(body)) + body


def _publish(topic: str, payload: str, qos: int, packet_id: int) -> bytes:
    header = 0x30 | ((qos & 0x03) << 1)
    body = _mqtt_string(topic)
    if qos > 0:
        body += packet_id.to_bytes(2, "big")
    body += payload.encode()
    return bytes([header]) + _mqtt_remaining_length(len(body)) + body


def _send(target: str, packet: bytes) -> None:
    with socket.create_connection((target, port_for("mqtt")), timeout=3) as connection:
        connection.sendall(packet)
        connection.recv(256)


def run(target: str, *, burst: int = 16, jitter: float = 0.2, seed: int = 21) -> dict:
    target = resolve_target(target)
    rng = random.Random(seed)
    start = now_iso()
    steps = []
    for number in range(1, max(1, burst) + 1):
        jitter_sleep(0, jitter, rng)
        client_id = f"probe-{rng.randint(1000, 9999)}"
        topic = rng.choice(_TOPICS)
        qos = rng.choice((0, 1, 2))
        kind = rng.choice(("connect", "subscribe", "publish"))
        if kind == "connect":
            packet = _connect(client_id)
        elif kind == "subscribe":
            packet = _subscribe(topic, qos, number)
        else:
            packet = _publish(topic, rng.choice(("1", "on", "reboot", "{}")), qos, number)
        started = now_iso()
        try:
            _send(target, packet)
            steps.append(step(number, "mqtt", "completed", started, f"{kind} {topic} qos{qos}"))
        except Exception as exc:
            steps.append(step(number, "mqtt", "failed", started, str(exc)))
    return build_summary(
        technique="mqtt-probing",
        target=target,
        expected_detection=EXPECTED_DETECTION,
        start_time=start,
        steps=steps,
        extra={"burst": burst},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--burst", type=int, default=16, help="number of bounded MQTT operations")
    parser.add_argument("--jitter", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=21)
    args = parser.parse_args()
    import json

    print(json.dumps(run(args.target, burst=args.burst, jitter=args.jitter, seed=args.seed), indent=2))


if __name__ == "__main__":
    main()
