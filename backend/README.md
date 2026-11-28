# backend/: the analysis API (FastAPI)

Reads telemetry from Elasticsearch and turns it into sessions, detections and
RL hardening decisions. It also serves everything the console shows and runs the
experiment lab. Elasticsearch is its only store.

```
backend/app/
├── main.py            app + router registration
├── config.py          every setting, from environment variables
├── security.py        API keys, roles, the authorization table, audit log
├── elastic.py         the Elasticsearch client wrapper (search, search_all, save)
├── schemas/           request/response models
├── rules/             Sigma-style detection rules (YAML), one file per domain
├── api/               one module per URL prefix: /events, /detections, /fleet, /adaptation, ...
├── services/          the logic (no HTTP in here)
│   ├── processor.py       the background loop: events -> sessions -> detections -> hardening
│   ├── normalizer.py      raw sensor record -> schema v2 event
│   ├── sessionizer.py     events -> attacker sessions
│   ├── detector.py        hybrid detection (rules + learned model + anomaly)
│   ├── detection/         rule engine, anomaly model, ATT&CK mapping, engine comparison
│   ├── ml/                the supervised detector: features, training, calibration
│   ├── hardening.py       the RL hardening agent (Thompson-sampling bandit)
│   ├── hardening_sim.py   offline training/evaluation of that agent
│   ├── fleet.py           which personas run on which sensor device
│   ├── personas.py        persona catalogue and versioned edits
│   └── experiments.py, experiment_lab.py, scenarios.py   the experiment lab
└── tools/             command-line jobs (python -m backend.app.tools.<name>)
    ├── train_detector.py   train + gate the learned detector
    ├── train_hardening.py  train + gate the RL hardening agent
    ├── train_anomaly.py    fit the isolation-forest anomaly model
    ├── compare_detectors.py, evaluate_detector.py, verify_attack.py, cleanup_internal_derived.py
```

Run it locally (needs Elasticsearch on 9200):

```bash
python -m uvicorn backend.app.main:app --reload       # API docs at http://127.0.0.1:8000/docs
```

Background: [architecture](../docs/reference/ARCHITECTURE.md), [detection](../docs/reference/DETECTION.md),
[RL hardening](../docs/reference/HARDENING.md), [security](../docs/reference/SECURITY.md).
