#!/usr/bin/env sh
# Thin POSIX wrapper around the cross-platform connect helper. On Windows, run
# `python scripts/pi/connect.py` directly instead. All arguments are forwarded.
set -eu
cd "$(dirname "$0")/../.."
if command -v python3 >/dev/null 2>&1; then
  exec python3 scripts/pi/connect.py "$@"
fi
exec python scripts/pi/connect.py "$@"
