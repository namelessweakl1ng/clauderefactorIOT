# ADR-0001: Keep Elasticsearch as the only store; no message broker

Status: accepted (2026-11-26)

## Context
The transformation brief invites Kafka/NATS/Redis/PostgreSQL. TRAPSIG ingests
lab-scale telemetry (a handful of Pi sensors, ≪1k events/s). Filebeat already
provides a durable 512 MB disk queue at the edge, Logstash normalises, and
Elasticsearch holds immutable raw events plus derived indices with stable IDs.

## Decision
Keep ES as the single system of record. Add new derived indices
(`trapsig-sensors`, `trapsig-network-*`, `trapsig-rule-state`, `trapsig-audit`,
`trapsig-model-*`, `trapsig-comparisons`) rather than a second database. Live
streaming uses Server-Sent Events backed by an ES timestamp watermark (pattern
taken from T-Pot Attack Map's `DataServer.py`, minus its Redis hop).

## Consequences
+ One durability/backup story (ES snapshots), one query language, no extra
  container on the analysis host (whose RAM is already dominated by ES+Kibana).
+ Restart/replica safety continues to come from content-derived IDs + lease.
− Live stream latency is bounded by the poll interval (default 2 s). Acceptable
  for research observation; revisit only if sub-second fan-out is measured as a need.
