# evaluation/: experiments and evidence

Tools that produce and analyse measured results. Run them from the repository
root as modules (`python -m evaluation.<tool>`).

| Tool | What it does |
| --- | --- |
| `run_matrix` | Plan or execute repeated scenario runs as experiments (arms via `--condition`, shuffled with `--seed`) |
| `arm_outcomes` | Per-arm attacker success (did RL hardening stop the attacker?), with a Wilson CI and a Fisher test |
| `measure_hardening` | Run every attack under each RL action on the in-process personas -> `hardening/outcomes.json` |
| `report` | Render a conservative Markdown report from measured data |
| `completeness` | Check that sensor JSONL events all reached Elasticsearch |
| `preflight`, `host_info`, `resources` | Clock sync check, host provenance, and Docker resource sampling for a run |

```bash
python -m evaluation.run_matrix --api-url http://127.0.0.1:8000 --attacker-ip <a> --target-ip <t> \
    --all-attacks --repetitions 5 --condition baseline --gap-seconds 30 --execute
python -m evaluation.arm_outcomes --api-url http://127.0.0.1:8000 --arm baseline=<batch> --arm rl-hardening=<batch>
python -m evaluation.measure_hardening && python -m backend.app.tools.train_hardening
```

* `hardening/` holds the measured RL outcome table and the latest training report (committed).
* `results/` holds per-run measured data from your lab (local only, git-ignored by policy).

Method: [EXPERIMENTS](../docs/research/EXPERIMENTS.md), [EVALUATION](../docs/research/EVALUATION.md).
