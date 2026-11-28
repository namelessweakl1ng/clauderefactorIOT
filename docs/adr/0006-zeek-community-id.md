# ADR-0006: Passive network intelligence via Zeek, joined by Community ID

Status: accepted (2026-11-26)

Zeek runs as an *optional* Compose profile (`netmon`) on the sensor, passively on
the honeypot interface, writing JSON `conn`/`dns`/`http`/`ssl` logs that Filebeat
ships. Logstash normalises them into `trapsig-network-*` (kept separate from
honeypot events so sessionisation and experiment semantics are unchanged). Both
Zeek (`policy/protocols/conn/community-id-logging`) and the TRAPSIG sensor emit
Community ID v1, so a network flow and the honeypot interaction it carried join
on an exact key instead of fuzzy time/port matching. Zeek is opt-in because it
costs ~150–250 MB RAM on a Pi; the default sensor footprint is unchanged.
