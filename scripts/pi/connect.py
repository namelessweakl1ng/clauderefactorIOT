#!/usr/bin/env python3
"""Fast reconnect to the Pi over Tailscale -- cross-platform (Linux and Windows).

Replaces the manual multi-step dance in docs/guides/SETUP.md with one command: it finds
the Pi's current Tailscale address (MagicDNS name preferred, since it survives the
Pi being re-imaged/re-authed), writes it into the laptop's .env as PI_HOST, and
re-runs the ssh-keyscan + fingerprint + known_hosts steps against the new address.

Because both machines keep a stable Tailscale address no matter which physical
network they are on (home router vs. phone hotspot), reconnecting after the Pi
moves is this one script run instead of editing LAN IPs by hand.

    python scripts/pi/connect.py                 # auto-detect pi named "trapsig-pi"
    python scripts/pi/connect.py --pi-name mypi   # a different Tailscale machine name

Only the laptop<->Pi management/telemetry path moves onto Tailscale. LAB_SUBNET
(used to validate attack targets) stays a real private LAN/hotspot subnet; the
threat model is unchanged.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINDOWS_TAILSCALE = r"C:\Program Files\Tailscale\tailscale.exe"


def _find(binary: str, windows_fallback: str | None = None) -> str | None:
    found = shutil.which(binary)
    if found:
        return found
    if windows_fallback and Path(windows_fallback).exists():
        return windows_fallback
    return None


def _tailscale_status(tailscale: str) -> dict:
    result = subprocess.run([tailscale, "status", "--json"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"`tailscale status` failed: {result.stderr.strip() or result.stdout.strip()}")
    return json.loads(result.stdout)


def _resolve_pi_address(status: dict, pi_name: str) -> tuple[str, str]:
    """Return (address, description) for the peer matching pi_name.

    Prefers the MagicDNS name over a raw 100.x address.
    """
    peers = list((status.get("Peer") or {}).values())
    self_node = status.get("Self")
    if self_node:
        peers.append(self_node)
    wanted = pi_name.lower()
    for peer in peers:
        hostname = (peer.get("HostName") or "").lower()
        dns = (peer.get("DNSName") or "").rstrip(".")
        if wanted in (hostname, dns.split(".")[0].lower()) or dns.lower().startswith(wanted + "."):
            if not peer.get("Online", True):
                print(f"WARNING: Tailscale peer '{pi_name}' is marked offline; continuing anyway.", file=sys.stderr)
            if dns:
                return dns, f"MagicDNS name for {hostname or pi_name}"
            ips = peer.get("TailscaleIPs") or []
            if ips:
                return ips[0], f"Tailscale IP for {hostname or pi_name}"
    raise RuntimeError(f"no Tailscale peer named '{pi_name}' found in `tailscale status` (is the Pi up on the tailnet?)")


def _update_env(env_file: Path, key: str, value: str) -> None:
    lines = env_file.read_text().splitlines() if env_file.exists() else []
    replaced = False
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = f"{key}={value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{key}={value}")
    env_file.write_text("\n".join(lines) + "\n")


def _refresh_known_hosts(address: str, port: int) -> int:
    keyscan = _find("ssh-keyscan")
    keygen = _find("ssh-keygen")
    if not keyscan:
        print("WARNING: ssh-keyscan not found; skipping known_hosts refresh. Install OpenSSH client.", file=sys.stderr)
        return 1
    secrets = ROOT / "secrets"
    secrets.mkdir(exist_ok=True)
    known_hosts = secrets / "known_hosts"
    result = subprocess.run([keyscan, "-H", "-p", str(port), address], capture_output=True, text=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        print(f"ERROR: ssh-keyscan found no host key for {address}:{port}. Is the Pi reachable over Tailscale?", file=sys.stderr)
        return 1
    known_hosts.write_text(result.stdout)
    try:
        os.chmod(known_hosts, 0o600)
    except OSError:
        pass
    print(f"Wrote host key(s) to {known_hosts}")
    if keygen:
        fingerprint = subprocess.run([keygen, "-lf", str(known_hosts)], capture_output=True, text=True, check=False)
        print("\nHost key fingerprint(s) -- COMPARE THESE WITH THE Pi CONSOLE before trusting:")
        print(fingerprint.stdout.strip() or "(none)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pi-name", default="trapsig-pi", help="the Pi's Tailscale machine name (default: trapsig-pi)")
    parser.add_argument("--env-file", default=str(ROOT / ".env"), help="laptop .env to update (default: ./.env)")
    parser.add_argument("--port", type=int, default=22, help="SSH management port on the Pi (default: 22)")
    parser.add_argument("--skip-known-hosts", action="store_true", help="only update PI_HOST, do not re-scan host keys")
    args = parser.parse_args()

    tailscale = _find("tailscale", WINDOWS_TAILSCALE)
    if not tailscale:
        print("ERROR: tailscale CLI not found. Install Tailscale and run `tailscale up` on both machines.", file=sys.stderr)
        return 2
    try:
        status = _tailscale_status(tailscale)
        address, description = _resolve_pi_address(status, args.pi_name)
    except (RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    env_file = Path(args.env_file)
    _update_env(env_file, "PI_HOST", address)
    print(f"Resolved {description}: {address}")
    print(f"Updated PI_HOST in {env_file}")

    code = 0 if args.skip_known_hosts else _refresh_known_hosts(address, args.port)
    print("\nReconnect complete." if code == 0 else "\nReconnect finished with warnings (see above).")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
