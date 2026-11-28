# ADR-0003: Additive event schema v2

Status: accepted (2026-11-26)

## Decision
Schema v2 adds, without removing or renaming any v1 field:
`persona.id`, `persona.name`, `persona.device_type`; `network.transport` taken
from the sensor (was hard-coded `tcp`); `network.community_id` (Community ID v1,
computed on the sensor from the 5-tuple); `trapsig.connection_id` and
`trapsig.sequence` (per-connection message order); and controlled protocol
namespaces `modbus.*`, `coap.*`, `rtsp.*`, `ftp.*`, `ssdp.*`, `dns.*`.
`trapsig.schema_version` becomes `"2"` for records carrying `raw.schema_version: 2`
(new sensors); legacy sensors still produce `"1"`.

## Consequences
Readers must tolerate either version — all backend code uses `.get()` paths.
Sessionisation still groups by source IP (unchanged semantics for experiments);
`connection_id` adds exact intra-session grouping for evidence.
