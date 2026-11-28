# Documentation

**New here?** Start with [CONNECT_AND_DEMO](guides/CONNECT_AND_DEMO.md), or run everything on one PC
(see the main [README](../README.md#run-everything-on-one-machine-no-pi-no-docker)).

## Guides: set it up

| Guide | Use it to |
| --- | --- |
| [CONNECT_AND_DEMO](guides/CONNECT_AND_DEMO.md) | Get from zero to a working demo (PC + Pi) |
| [SETUP](guides/SETUP.md) | Analysis host and Pi setup in detail; Tailscale; troubleshooting |
| [DEPLOYMENT](guides/DEPLOYMENT.md) | Spread the 16 personas over several devices (Pi OS Lite, Linux, Windows) |

## Reference: how it works

| Doc | Topic |
| --- | --- |
| [ARCHITECTURE](reference/ARCHITECTURE.md) | Components and data flow |
| [PERSONAS](reference/PERSONAS.md) | Device personas: format, protocols, adding one |
| [SCENARIOS](reference/SCENARIOS.md) | The 67 attack and control scenarios (generated) |
| [DETECTION](reference/DETECTION.md) | Rules, learned model, anomaly engine, hybrid merge |
| [HARDENING](reference/HARDENING.md) | The RL hardening agent: actions, reward, training, results |
| [EVENT_SCHEMA](reference/EVENT_SCHEMA.md) | Event fields (schema v2) |
| [SECURITY](reference/SECURITY.md) | API keys, roles, audit, sensor safety limits |

## Research: measuring it

| Doc | Topic |
| --- | --- |
| [EXPERIMENTS](research/EXPERIMENTS.md) | Experiment lifecycle, conditions/arms, ground truth |
| [EVALUATION](research/EVALUATION.md) | Metrics, comparisons, what counts as evidence |

## Project

| Doc | Topic |
| --- | --- |
| [ROADMAP](project/ROADMAP.md) | Audit and outstanding work |
| [IMPLEMENTATION_LOG](project/IMPLEMENTATION_LOG.md) | What was built, verified results, lab evidence |
| [adr/](adr/) | Architecture decision records |
