# tests/

```bash
python -m pytest -q          # everything (about 2 minutes, no Elasticsearch needed)
python -m pytest tests/safety -q
```

| Folder | Covers |
| --- | --- |
| `backend/` | API, security, processor (incl. incremental mode), fleet, RL agent and its training |
| `detection/` | rule engine, embedded rule tests, hybrid detector |
| `ingestion/` | Logstash/normalizer parity, schema v2, deployment and compose contracts |
| `sensor/` | protocol plugins, personas, the fleet agent (hot reload, shipping) |
| `safety/` | **closed loop**: real attack runner -> real personas on loopback -> normalizer -> detector, for every persona scenario; RL hardening outcome checks; scenario manifest contracts |
| `experiments/`, `evaluation/` | experiment lifecycle and regressions, arm comparison, run matrix, lab tooling |
| `sessionization/` | session reconstruction |
| `test_repository_contracts.py`, `test_docs_links.py` | repository-wide rules; every Markdown link resolves |

Tests never touch the network beyond 127.0.0.1.
