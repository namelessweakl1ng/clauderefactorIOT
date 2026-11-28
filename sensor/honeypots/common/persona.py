"""Declarative device personas: TOML on disk, JSON over the API, one validator.

A persona describes *one fictional device*: identity, fingerprint, accepted
honey-credentials, logging and interaction bounds, and the protocol services it
exposes. It is the single source of truth for both the sensor runtime and the
backend management API (which imports this module from a read-only mount), so
a persona the API accepts is exactly a persona the sensor can run.

Only the Python standard library is used (``tomllib``), keeping the sensor image
dependency-free.
"""

from __future__ import annotations

import json
import re
import tomllib
import urllib.request
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

import plugins  # noqa: F401  (registers every protocol plugin)

from common.plugin import REGISTRY, PersonaContext, PluginConfigError

DEVICE_TYPES = (
    "router",
    "ip_camera",
    "doorbell",
    "industrial_plc",
    "mqtt_gateway",
    "building_controller",
    "nas",
    "embedded_linux",
    "iiot_gateway",
    "tank_gauge",
    "drive",
    "hmi",
    "voip_phone",
    "printer",
    "dvr",
    "workstation",
    "server",
    "generic",
)
_ID = re.compile(r"^[a-z][a-z0-9\-]{1,40}$")
_SERVICE = re.compile(r"^[a-z][a-z0-9\-]{1,40}$")
_TOP_LEVEL = {
    "id",
    "name",
    "device_type",
    "vendor",
    "model",
    "firmware",
    "description",
    "enabled",
    "fingerprint",
    "credentials",
    "logging",
    "interaction",
    "services",
    "version",
}


class PersonaError(ValueError):
    """The persona definition is invalid; the message names the field."""


@dataclass
class ServiceSpec:
    name: str
    plugin: str
    port: int
    public_port: int
    enabled: bool
    honeypot_id: str | None
    options: dict[str, Any]


@dataclass
class Persona:
    id: str
    name: str
    device_type: str
    vendor: str
    model: str
    firmware: str
    description: str
    enabled: bool
    version: int
    fingerprint: dict[str, Any]
    credentials: tuple[tuple[str, str], ...]
    logging: dict[str, Any]
    max_messages: int
    max_seconds: float
    services: list[ServiceSpec] = field(default_factory=list)
    source: dict[str, Any] = field(default_factory=dict)

    @property
    def hostname(self) -> str:
        return str(self.fingerprint.get("hostname") or self.id)

    def context(self) -> PersonaContext:
        return PersonaContext(self.id, self.name, self.device_type, self.vendor, self.model, self.firmware, self.hostname, self.credentials)

    def content_sha256(self) -> str:
        return sha256(json.dumps(self.source, sort_keys=True).encode()).hexdigest()

    def bindings(self) -> list[Any]:
        from common.runtime import ServiceBinding

        out = []
        context = self.context()
        for spec in self.services:
            if not spec.enabled:
                continue
            cls = REGISTRY[spec.plugin]
            plugin = cls(context, spec.options)
            out.append(
                ServiceBinding(
                    plugin=plugin,
                    service_name=spec.name,
                    port=spec.port,
                    public_port=spec.public_port,
                    max_messages=min(self.max_messages, cls.max_messages_limit),
                    max_seconds=min(self.max_seconds, cls.max_seconds_limit),
                    honeypot_id=spec.honeypot_id,
                )
            )
        return out

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "model": self.model,
            "firmware": self.firmware,
            "description": self.description,
            "enabled": self.enabled,
            "version": self.version,
            "fingerprint": dict(self.fingerprint),
            "credential_count": len(self.credentials),
            "logging": dict(self.logging),
            "interaction": {"max_messages": self.max_messages, "max_seconds": self.max_seconds},
            "services": [
                {
                    "name": s.name,
                    "plugin": s.plugin,
                    "protocol": REGISTRY[s.plugin].protocol,
                    "transport": REGISTRY[s.plugin].transport,
                    "interaction": REGISTRY[s.plugin].interaction,
                    "port": s.port,
                    "public_port": s.public_port,
                    "enabled": s.enabled,
                }
                for s in self.services
            ],
            "content_sha256": self.content_sha256(),
        }


def _require(data: dict[str, Any], key: str, kind: type, where: str) -> Any:
    if key not in data:
        raise PersonaError(f"{where}: missing '{key}'")
    value = data[key]
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise PersonaError(f"{where}: '{key}' must be {kind.__name__}")
    return value


def _port(value: Any, where: str, *, unprivileged: bool) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PersonaError(f"{where} must be an integer")
    low = 1024 if unprivileged else 1
    if not low <= value <= 65535:
        raise PersonaError(
            f"{where} must be within {low}-65535" + (" (containers never bind privileged ports; map them with public_port)" if unprivileged else "")
        )
    return value


def parse_persona(data: dict[str, Any]) -> Persona:
    """Validate a persona mapping (from TOML or JSON) and return a :class:`Persona`."""
    if not isinstance(data, dict):
        raise PersonaError("persona must be a mapping")
    unknown = set(data) - _TOP_LEVEL
    if unknown:
        raise PersonaError(f"unknown top-level field(s): {sorted(unknown)}")
    pid = _require(data, "id", str, "persona")
    if not _ID.match(pid):
        raise PersonaError("persona: 'id' must be lower-case kebab-case (2-41 chars)")
    where = f"persona {pid}"
    name = _require(data, "name", str, where)
    device_type = _require(data, "device_type", str, where)
    if device_type not in DEVICE_TYPES:
        raise PersonaError(f"{where}: device_type must be one of {DEVICE_TYPES}")
    fingerprint = data.get("fingerprint") or {}
    if not isinstance(fingerprint, dict):
        raise PersonaError(f"{where}: fingerprint must be a table")
    credentials = []
    for index, pair in enumerate((data.get("credentials") or {}).get("accept", []) if isinstance(data.get("credentials"), dict) else []):
        if not (isinstance(pair, list) and len(pair) == 2 and all(isinstance(x, str) and len(x) <= 128 for x in pair)):
            raise PersonaError(f"{where}: credentials.accept[{index}] must be [username, password]")
        credentials.append((pair[0], pair[1]))
    logging = data.get("logging") or {}
    if not isinstance(logging, dict):
        raise PersonaError(f"{where}: logging must be a table")
    if logging.get("credentials", "full") not in {"full", "redact"}:
        raise PersonaError(f"{where}: logging.credentials must be 'full' or 'redact'")
    payload_bytes = logging.get("payload_bytes", 256)
    if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool) or not 0 <= payload_bytes <= 4096:
        raise PersonaError(f"{where}: logging.payload_bytes must be 0-4096")
    interaction = data.get("interaction") or {}
    max_messages = interaction.get("max_messages", 64)
    max_seconds = interaction.get("max_seconds", 120)
    if not isinstance(max_messages, int) or isinstance(max_messages, bool) or not 1 <= max_messages <= 1024:
        raise PersonaError(f"{where}: interaction.max_messages must be 1-1024")
    if not isinstance(max_seconds, (int, float)) or isinstance(max_seconds, bool) or not 1 <= max_seconds <= 3600:
        raise PersonaError(f"{where}: interaction.max_seconds must be 1-3600")
    raw_services = data.get("services")
    if not isinstance(raw_services, list) or not raw_services:
        raise PersonaError(f"{where}: at least one [[services]] entry is required")
    services: list[ServiceSpec] = []
    bound: set[tuple[str, int]] = set()
    published: set[tuple[str, int]] = set()
    names: set[str] = set()
    context = PersonaContext(
        pid,
        name,
        device_type,
        str(data.get("vendor", "")),
        str(data.get("model", "")),
        str(data.get("firmware", "")),
        str(fingerprint.get("hostname") or pid),
        tuple(credentials),
    )
    for index, raw in enumerate(raw_services):
        swhere = f"{where}: services[{index}]"
        if not isinstance(raw, dict):
            raise PersonaError(f"{swhere} must be a table")
        plugin = _require(raw, "plugin", str, swhere)
        if plugin not in REGISTRY:
            raise PersonaError(f"{swhere}: unknown plugin {plugin!r}; available: {sorted(REGISTRY)}")
        cls = REGISTRY[plugin]
        service_name = raw.get("name", plugin)
        if not isinstance(service_name, str) or not _SERVICE.match(service_name):
            raise PersonaError(f"{swhere}: name must be kebab-case")
        if service_name in names:
            raise PersonaError(f"{swhere}: duplicate service name {service_name!r}")
        names.add(service_name)
        port = _port(raw.get("port", cls.default_port), f"{swhere}: port", unprivileged=True)
        public_port = _port(raw.get("public_port", port), f"{swhere}: public_port", unprivileged=False)
        for registry, key, label in ((bound, (cls.transport, port), "port"), (published, (cls.transport, public_port), "public_port")):
            if key in registry:
                raise PersonaError(f"{swhere}: {cls.transport}/{key[1]} {label} is already used")
            registry.add(key)
        options = raw.get("options") or {}
        if not isinstance(options, dict):
            raise PersonaError(f"{swhere}: options must be a table")
        try:
            cls(context, options)  # plugin-level validation
        except PluginConfigError as exc:
            raise PersonaError(f"{swhere}: {exc}") from exc
        honeypot_id = raw.get("honeypot_id")
        if honeypot_id is not None and (not isinstance(honeypot_id, str) or not _SERVICE.match(honeypot_id.replace("_", "-"))):
            raise PersonaError(f"{swhere}: honeypot_id must be kebab-case")
        services.append(ServiceSpec(service_name, plugin, port, public_port, bool(raw.get("enabled", True)), honeypot_id, options))
    version = data.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise PersonaError(f"{where}: version must be a positive integer")
    return Persona(
        id=pid,
        name=name,
        device_type=device_type,
        vendor=str(data.get("vendor", "")),
        model=str(data.get("model", "")),
        firmware=str(data.get("firmware", "")),
        description=str(data.get("description", "")),
        enabled=bool(data.get("enabled", True)),
        version=version,
        fingerprint=dict(fingerprint),
        credentials=tuple(credentials),
        logging={"credentials": logging.get("credentials", "full"), "payload_bytes": payload_bytes},
        max_messages=max_messages,
        max_seconds=float(max_seconds),
        services=services,
        source=json.loads(json.dumps(data)),
    )


def load_persona_file(path: str | Path) -> Persona:
    with open(path, "rb") as stream:
        return parse_persona(tomllib.load(stream))


def load_directory(directory: str | Path) -> dict[str, Persona]:
    personas: dict[str, Persona] = {}
    for path in sorted(Path(directory).glob("*.toml")):
        persona = load_persona_file(path)
        if persona.id in personas:
            raise PersonaError(f"duplicate persona id {persona.id!r} in {path.name}")
        personas[persona.id] = persona
    return personas


def load_effective(persona_id: str, directory: str | Path, *, url: str | None = None, api_key: str | None = None, timeout: float = 3.0) -> tuple[Persona, str]:
    """Return ``(persona, origin)``: the backend's active version if reachable and
    valid, otherwise the baked-in file. Never fails over to an invalid definition."""
    if url:
        try:
            headers = {"User-Agent": "trapsig-sensor/2"}
            if api_key:
                headers["X-API-Key"] = api_key
            request = urllib.request.Request(f"{url.rstrip('/')}/personas/{persona_id}/effective", headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed lab backend URL
                document = json.loads(response.read(256_000).decode("utf-8"))
            persona = parse_persona(document.get("definition", document))
            if persona.id == persona_id:
                return persona, "backend"
        except Exception:
            pass
    personas = load_directory(directory)
    if persona_id not in personas:
        raise PersonaError(f"persona {persona_id!r} not found in {directory}")
    return personas[persona_id], "file"
