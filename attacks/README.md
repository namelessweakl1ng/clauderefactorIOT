# attacks/: controlled lab attacker

Bounded attack and control traffic for the lab, with ground truth. Never point
it at anything you do not own: the runner refuses any target outside `LAB_SUBNET`.

```
attacks/
├── scenarios/      67 YAML manifests (55 attacks, 12 controls), catalogue in docs/reference/SCENARIOS.md
├── runner/
│   ├── run.py          execute one manifest against one target; writes ground truth
│   ├── protocols.py    Modbus, CoAP, RTSP, FTP, SSDP, DNS clients
│   ├── ot_it.py        S7, BACnet, EtherNet/IP, tank gauge, telnet, SNMP, Redis, SIP, TFTP, VNC, RDP clients
│   ├── inprocess.py    all personas on loopback, for the closed-loop tests and hardening measurement
│   └── safety.py       target validation
├── realistic/      varied (multi-threaded, randomized) traffic generators for detector training
├── credentials/    small public default-credential wordlists used by the scenarios
└── runs/           local ground-truth output (git-ignored)
```

```bash
pip install -r attacks/requirements.txt
export LAB_SUBNET=192.168.50.0/24
python -m attacks.runner.run s7-plc-stop --target 192.168.50.10
python -m attacks.runner.run s7-plc-stop --target 192.168.50.10 --experiment-id EXP-... --api-url http://<analysis>:8000
python -m attacks.realistic.credential_stuffing --target 192.168.50.10 ...
```

## Safety boundary

* `runner/safety.py` accepts only one usable private, non-loopback address inside a
  private `LAB_SUBNET`. Network, broadcast, loopback and public addresses are
  rejected before any traffic. Nothing discovers hosts or iterates ranges.
* Every step is capped: at most 64 requests per step, 64 credential attempts, and
  120 s of pacing per step, with short socket timeouts.
* No real payloads. Dropper URLs point at the unroutable TEST-NET range; TFTP and
  FTP transfers are refused by the decoys; Redis "writes" are acknowledged and
  discarded by the decoy; shells are emulated.

## Output

Every run writes a JSON ground-truth summary to `attacks/runs/`: the manifest
SHA-256, timestamps, expected detection, and per-step outcome (`completed`, or
`rejected` when the decoy refused at protocol level). With `--experiment-id` and
`--api-url`, the summary is also submitted to the experiment. A step's allowed
outcomes come from `backend/app/services/scenario_contract.py`.

Add a scenario by writing a YAML manifest (copy a similar one), then run
`python scripts/dev/scenario_catalog.py` to regenerate the catalogue. The
closed-loop test in `tests/safety/` picks it up automatically.
