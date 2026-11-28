# ADR-0002: Protocol plugins + declarative device personas on the sensor

Status: accepted (2026-11-26)

## Context
Each custom honeypot was a hard-coded Python class bound 1:1 to a container and
an env var. Adding a device meant writing code; protocols were TCP-only and
single-request. References: RIoTPot (service interface with id/name/network/port
and a middleware chain applied to every connection), OpenCanary (config-driven
modules, `honeycreds`), Conpot (declarative device templates — GPL-2, so ideas
only, no code reuse).

## Decision
* `sensor/honeypots/common/plugin.py` defines a `ProtocolPlugin` contract:
  `name`, `transport` (`tcp`/`udp`), a bounded *framer*, and a per-connection
  `Conversation` that returns `(reply, events, close)` for each message, bounded by
  `max_messages` and `max_seconds`.
* A registry maps plugin names to classes; the four legacy personas are adapted
  as plugins unchanged, so their tests and behaviour stay byte-identical.
* Personas are YAML (`sensor/personas/*.yaml`): identity, fingerprint, banners,
  credentials, and a list of services `{plugin, port, options}`. One process can
  host several services (threads), keeping Pi RAM roughly flat per persona.
* Ports <1024 are never bound inside containers (no `CAP_NET_BIND_SERVICE`);
  Compose maps e.g. host 502 → container 5020.
* UDP plugins pass through a reflection guard: reply ≤ `max(request, 512)` bytes
  ×3 and a per-source token bucket, so a spoofed source cannot use the sensor as
  an amplifier.

## Consequences
+ New device = YAML file; new protocol = one plugin module with unit tests that
  need no sockets.
+ Legacy `SERVICE=camera` etc. keep working.
− Interaction remains deliberately low/medium; no protocol executes attacker input.
