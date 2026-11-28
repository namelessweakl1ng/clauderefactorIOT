"""HTTP path/parameter fuzzing against the camera/router HTTP personas.

A larger, varied path list than the fixed scenarios, randomized ordering, varied
User-Agents, and optional light query-parameter variation. Non-adaptive: the path
set and ordering are fixed from the seed before any request.

    python -m attacks.realistic.http_fuzzing --target 192.168.50.10 --service camera
"""

import argparse
import http.cookiejar
import random
from urllib.request import HTTPCookieProcessor, Request, build_opener

from .common import USER_AGENTS, build_summary, jitter_sleep, now_iso, port_for, resolve_target, step

EXPECTED_DETECTION = "WEB_ENUMERATION"

_PATHS = (
    "/", "/login", "/admin", "/config", "/status", "/setup", "/system", "/network", "/device",
    "/firmware", "/maintenance", "/live", "/snapshot", "/stream", "/dashboard", "/wifi", "/lan",
    "/dhcp", "/clients", "/logs", "/internet", "/cgi-bin/", "/api/status", "/backup", "/.git/config",
    "/robots.txt", "/favicon.ico", "/shell", "/debug", "/console",
)
_QUERY_KEYS = ("id", "page", "debug", "lang", "redirect")


def _fetch(target: str, service: str, path: str, number: int, rng: random.Random) -> dict:
    started = now_iso()
    query = f"?{rng.choice(_QUERY_KEYS)}={rng.randint(1, 999)}" if rng.random() < 0.3 else ""
    url = f"http://{target}:{port_for(service)}{path}{query}"
    headers = {"User-Agent": rng.choice(USER_AGENTS)}
    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        opener.open(Request(url, headers=headers), timeout=3).read(512)
        return step(number, service, "completed", started, f"{path}{query}")
    except Exception as exc:
        # 401/403/404 are expected outcomes of enumeration, not script failures.
        if getattr(exc, "code", None) in (401, 403, 404):
            return step(number, service, "rejected", started, f"{path} -> {exc.code}")
        return step(number, service, "failed", started, str(exc))


def run(target: str, *, service: str = "camera", paths: int = 24, jitter: float = 0.25, seed: int = 99) -> dict:
    target = resolve_target(target)
    rng = random.Random(seed)
    chosen = list(_PATHS)
    rng.shuffle(chosen)
    chosen = chosen[: min(paths, len(chosen))]
    start = now_iso()
    steps = []
    for number, path in enumerate(chosen, 1):
        jitter_sleep(0, jitter, rng)
        steps.append(_fetch(target, service, path, number, rng))
    return build_summary(
        technique="http-fuzzing",
        target=target,
        expected_detection=EXPECTED_DETECTION,
        start_time=start,
        steps=steps,
        extra={"service": service, "distinct_paths": len(chosen)},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--service", default="camera", choices=("camera", "router", "http"))
    parser.add_argument("--paths", type=int, default=24)
    parser.add_argument("--jitter", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=99)
    args = parser.parse_args()
    import json

    print(json.dumps(run(args.target, service=args.service, paths=args.paths, jitter=args.jitter, seed=args.seed), indent=2))


if __name__ == "__main__":
    main()
