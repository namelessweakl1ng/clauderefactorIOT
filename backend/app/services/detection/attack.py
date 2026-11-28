"""Curated MITRE ATT&CK (Enterprise + ICS) subset relevant to IoT honeypots.

Only techniques a TRAPSIG sensor can actually observe are listed. Names and
tactics follow MITRE ATT&CK (https://attack.mitre.org, content © The MITRE
Corporation, used under the ATT&CK Terms of Use). :func:`verify_against_stix`
checks this table against an ``attack-stix-data`` bundle
(https://github.com/mitre-attack/attack-stix-data) so drift is detectable:

    python -m backend.app.tools.verify_attack enterprise-attack.json ics-attack.json

Mapping a honeypot detection to a technique is an analyst judgement, not a
measurement; the API labels these as ``mapping: "rule-tag"`` (asserted by the
rule author) or ``mapping: "type-default"`` (project default for an ML type).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

TECHNIQUES: dict[str, dict[str, Any]] = {
    # ---- Enterprise ------------------------------------------------------- #
    "T1595": {"name": "Active Scanning", "tactics": ["reconnaissance"], "domain": "enterprise"},
    "T1595.001": {"name": "Scanning IP Blocks", "tactics": ["reconnaissance"], "domain": "enterprise"},
    "T1595.002": {"name": "Vulnerability Scanning", "tactics": ["reconnaissance"], "domain": "enterprise"},
    "T1595.003": {"name": "Wordlist Scanning", "tactics": ["reconnaissance"], "domain": "enterprise"},
    "T1592": {"name": "Gather Victim Host Information", "tactics": ["reconnaissance"], "domain": "enterprise"},
    "T1046": {"name": "Network Service Discovery", "tactics": ["discovery"], "domain": "enterprise"},
    "T1082": {"name": "System Information Discovery", "tactics": ["discovery"], "domain": "enterprise"},
    "T1033": {"name": "System Owner/User Discovery", "tactics": ["discovery"], "domain": "enterprise"},
    "T1083": {"name": "File and Directory Discovery", "tactics": ["discovery"], "domain": "enterprise"},
    "T1110": {"name": "Brute Force", "tactics": ["credential-access"], "domain": "enterprise"},
    "T1110.001": {"name": "Password Guessing", "tactics": ["credential-access"], "domain": "enterprise"},
    "T1110.003": {"name": "Password Spraying", "tactics": ["credential-access"], "domain": "enterprise"},
    "T1110.004": {"name": "Credential Stuffing", "tactics": ["credential-access"], "domain": "enterprise"},
    "T1078": {"name": "Valid Accounts", "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"], "domain": "enterprise"},
    "T1078.001": {"name": "Default Accounts", "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"], "domain": "enterprise"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "domain": "enterprise"},
    "T1133": {"name": "External Remote Services", "tactics": ["persistence", "initial-access"], "domain": "enterprise"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["execution"], "domain": "enterprise"},
    "T1059.004": {"name": "Unix Shell", "tactics": ["execution"], "domain": "enterprise"},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ["command-and-control"], "domain": "enterprise"},
    "T1071": {"name": "Application Layer Protocol", "tactics": ["command-and-control"], "domain": "enterprise"},
    # ---- ICS -------------------------------------------------------------- #
    "T0846": {"name": "Remote System Discovery", "tactics": ["discovery"], "domain": "ics"},
    "T0888": {"name": "Remote System Information Discovery", "tactics": ["discovery"], "domain": "ics"},
    "T0840": {"name": "Network Connection Enumeration", "tactics": ["discovery"], "domain": "ics"},
    "T0861": {"name": "Point & Tag Identification", "tactics": ["collection"], "domain": "ics"},
    "T0801": {"name": "Monitor Process State", "tactics": ["collection"], "domain": "ics"},
    "T0855": {"name": "Unauthorized Command Message", "tactics": ["impair-process-control"], "domain": "ics"},
    "T0836": {"name": "Modify Parameter", "tactics": ["impair-process-control"], "domain": "ics"},
    "T0812": {"name": "Default Credentials", "tactics": ["lateral-movement"], "domain": "ics"},
    "T0883": {"name": "Internet Accessible Device", "tactics": ["initial-access"], "domain": "ics"},
}

TACTIC_ORDER = (
    "reconnaissance",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "impair-process-control",
    "impact",
)

# Project defaults for detection types emitted by engines that carry no tags
# (the supervised policy and the anomaly engine). Rule tags take precedence.
TYPE_DEFAULTS: dict[str, tuple[str, ...]] = {
    "RECONNAISSANCE": ("T1595", "T1046"),
    "BRUTE_FORCE": ("T1110.001",),
    "DEFAULT_CREDENTIALS": ("T1078.001",),
    "WEB_ENUMERATION": ("T1595.003",),
    "COMMAND_INTERACTION": ("T1059.004",),
    "MQTT_PROBING": ("T1046", "T0861"),
    "MULTI_SERVICE_ACTIVITY": ("T1046",),
    "MULTI_STAGE_ATTACK": (),
    "EXPLOIT_ATTEMPT": ("T1190",),
    "MALWARE_DOWNLOAD": ("T1105",),
    "UNAUTHORIZED_COMMAND": ("T0855",),
    "ICS_RECONNAISSANCE": ("T0888", "T0846"),
    "ICS_WRITE": ("T0855", "T0836"),
    "ANOMALOUS_BEHAVIOUR": (),
}


def technique(identifier: str) -> dict[str, Any] | None:
    entry = TECHNIQUES.get(identifier.upper())
    return {"id": identifier.upper(), **entry} if entry else None


def describe(identifiers: Iterable[str], mapping: str) -> list[dict[str, Any]]:
    """Expand technique IDs into catalogue entries; unknown IDs are kept and flagged."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for identifier in identifiers:
        key = identifier.upper()
        if key in seen:
            continue
        seen.add(key)
        entry = technique(key)
        out.append({**(entry or {"id": key, "name": None, "tactics": [], "domain": None}), "known": entry is not None, "mapping": mapping})
    return out


def _stix_external_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references") or []:
        if reference.get("source_name") in {"mitre-attack", "mitre-ics-attack"} and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def verify_against_stix(bundles: Iterable[Path | str | dict[str, Any]]) -> dict[str, Any]:
    """Compare the catalogue with ATT&CK STIX bundles; return mismatches.

    Returns ``{"checked": n, "missing": [...], "renamed": [...], "deprecated": [...]}``.
    Revoked/deprecated techniques are reported so mappings can be updated.
    """
    stix: dict[str, dict[str, Any]] = {}
    for bundle in bundles:
        data = bundle if isinstance(bundle, dict) else json.loads(Path(bundle).read_text(encoding="utf-8"))
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            identifier = _stix_external_id(obj)
            if identifier:
                stix[identifier] = obj
    missing, renamed, deprecated = [], [], []
    for identifier, entry in TECHNIQUES.items():
        obj = stix.get(identifier)
        if obj is None:
            missing.append(identifier)
            continue
        if obj.get("name") != entry["name"]:
            renamed.append({"id": identifier, "catalogue": entry["name"], "stix": obj.get("name")})
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            deprecated.append(identifier)
    return {"checked": len(TECHNIQUES), "stix_techniques": len(stix), "missing": missing, "renamed": renamed, "deprecated": deprecated}
