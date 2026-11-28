# scripts/: helpers, grouped by job

Run everything from the repository root.

| Folder | For | Commands |
| --- | --- | --- |
| `lab/` | The whole stack on **one PC**, no Pi, no Docker | `python scripts/lab/local_lab.py up --elastic-home ../local-stack --sensor-ip 172.23.64.1` (then `status`, `down`, `restart-backend`) |
| `pi/` | Connecting the laptop and the Pi over Tailscale | `python scripts/pi/connect.py` (POSIX wrapper: `scripts/pi/connect.sh`) |
| `analysis-host/` | The Docker analysis stack | `scripts/analysis-host/up.sh`, `down.sh`, `status.sh` |
| `dev/` | Development checks | `scripts/dev/test.sh` (pytest), `validate.sh` (compose + shell + tests + build), `preflight.sh`, `benchmark.py`, `scenario_catalog.py` (regenerates docs/reference/SCENARIOS.md) |
| `ci/` | Used by GitHub Actions | compose-mount check, shell syntax check, integration smoke test |

The Pi's own scripts (`setup.sh`, `start.sh`, ...) live in `sensor/scripts/`
because they run on the Pi. Experiment tools are in `evaluation/`, and model
training is in `backend/app/tools/`.
