"""RL hardening agent: policy, reward, learning, store cycle, sensor enforcement."""

import asyncio
import random
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.app.services import hardening as rl

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))


# ---- pure policy ---------------------------------------------------------------- #


def test_stage_is_the_furthest_kill_chain_step():
    assert rl.stage_for(["RECONNAISSANCE"]) == "recon"
    assert rl.stage_for(["RECONNAISSANCE", "BRUTE_FORCE"]) == "credential"
    assert rl.stage_for(["BRUTE_FORCE", "MALWARE_DOWNLOAD"]) == "intrusion"
    assert rl.stage_for(["ICS_RECONNAISSANCE", "ICS_WRITE"]) == "ics_impact"
    assert rl.stage_for([]) == "recon"


def test_choice_is_deterministic_and_explained():
    posteriors = rl.empty_posteriors()
    first = rl.choose("credential|it|new", posteriors, list(rl.ACTIONS), random.Random(7))
    second = rl.choose("credential|it|new", posteriors, list(rl.ACTIONS), random.Random(7))
    assert first == second
    assert first["action"] in rl.ACTIONS and first["reason"] and set(first["samples"]) == set(rl.ACTIONS)


def test_safety_floor_only_allows_write_blocking_actions_in_ics_impact():
    """Regression: an explored deny_auth let an S7 PLC stop succeed (S7 has no login)."""
    posteriors = rl.empty_posteriors()
    for action in ("observe", "tarpit", "deny_auth"):  # even if these looked great
        posteriors["ics_impact|ot|returning"][action].update(alpha=500.0, beta=1.0)
    for seed in range(100):
        pick = rl.choose("ics_impact|ot|returning", posteriors, list(rl.ACTIONS), random.Random(seed))
        assert pick["action"] in {"read_only", "quarantine"} and "safety floor" in pick["reason"]
    assert rl.allowed_for("credential|it|new", list(rl.ACTIONS))[0] == list(rl.ACTIONS)  # other stages unrestricted


def test_allowed_actions_restrict_the_arms(monkeypatch):
    monkeypatch.setenv("HARDENING_ALLOWED_ACTIONS", "observe,tarpit")
    assert rl.config()["allowed_actions"] == ["observe", "tarpit"]
    pick = rl.choose("recon|it|new", rl.empty_posteriors(), rl.config()["allowed_actions"], random.Random(1))
    assert pick["action"] in {"observe", "tarpit"}


def event(action="request", category="web", outcome="unknown", **extra):
    return {"event": {"action": action, "category": category, "outcome": outcome}, "service": {"name": extra.pop("service", "camera")}, **extra}


def test_reward_penalises_attacker_success_and_values_new_intelligence():
    success = rl.score_outcome([event("login_attempt", "authentication", "success")])
    assert success["harm_events"] == 1 and success["reward"] < 0
    intel = rl.score_outcome([event(url={"path": f"/p{i}"}) for i in range(8)])
    assert intel["harm_events"] == 0 and intel["intel"] == 1.0 and intel["reward"] == pytest.approx(1.0)
    seen = rl.score_outcome([event(url={"path": "/p0"})], {rl.behaviour_key(event(url={"path": "/p0"}))})
    assert seen["new_behaviours"] == 0
    assert rl.score_outcome([])["reward"] == 0.0  # attacker left: no harm, no intel
    blocked_write = event("write_single_register", "network", "failure", service="modbus", modbus={"write": True, "function_code": 6})
    assert not rl.is_harm(blocked_write)
    assert rl.is_harm({**blocked_write, "event": {**blocked_write["event"], "outcome": "success"}})


def test_bandit_learns_the_best_action_per_context():
    """Simulated attackers: in the credential stage, deny_auth keeps them guessing
    (engaged, revealing wordlists) without letting them in; observe lets them in;
    quarantine makes them leave. In recon, observing is best (nothing to protect yet)."""
    true_reward = {
        "credential|it|new": {"observe": -0.6, "tarpit": -0.2, "deny_auth": 0.7, "read_only": -0.5, "quarantine": 0.1},
        "recon|it|new": {"observe": 0.8, "tarpit": 0.5, "deny_auth": 0.4, "read_only": 0.6, "quarantine": 0.0},
    }
    posteriors = rl.empty_posteriors()
    rng = random.Random(42)
    late: dict[str, list[str]] = {c: [] for c in true_reward}
    for episode in range(400):
        context = "credential|it|new" if episode % 2 else "recon|it|new"
        pick = rl.choose(context, posteriors, list(rl.ACTIONS), rng)
        reward = max(-1.0, min(1.0, true_reward[context][pick["action"]] + rng.gauss(0, 0.2)))
        rl.update(posteriors, context, pick["action"], reward)
        if episode >= 300:
            late[context].append(pick["action"])
    for context, rewards in true_reward.items():
        best = max(rewards, key=rewards.get)
        means = {a: rl.posterior_mean(posteriors[context][a]) for a in rl.ACTIONS}
        assert max(means, key=means.get) == best
        assert late[context].count(best) / len(late[context]) > 0.6


# ---- store-backed cycle ----------------------------------------------------------- #


class FakeStore:
    def __init__(self):
        self.docs: dict[str, dict[str, dict]] = {}

    async def save(self, index, document_id, document, *, refresh="wait_for"):
        self.docs.setdefault(index, {})[document_id] = dict(document)
        return document

    async def get(self, index, document_id):
        doc = self.docs.get(index, {}).get(document_id)
        return {**doc, "_id": document_id} if doc else None

    async def search(self, index, query=None, size=100, sort_field="@timestamp", missing_index_is_empty=False):
        docs = [{**d, "_id": k} for k, d in self.docs.get(index, {}).items()]
        if query and "term" in query:
            ((field, value),) = query["term"].items()
            docs = [d for d in docs if d.get(field) == value]
        return sorted(docs, key=lambda d: str(d.get(sort_field, "")), reverse=True)[:size]

    async def search_all(self, index, query=None, *, sort=None, page_size=500, missing_index_is_empty=False):
        source = query["bool"]["filter"][0]["bool"]["should"][0]["term"]["source.ip"]
        window = query["bool"]["filter"][1]["range"]["@timestamp"]
        events = [e for i, d in self.docs.items() if i.startswith("trapsig-events") for e in d.values()]
        return [e for e in events if e["source"]["ip"] == source and window["gte"] <= e["@timestamp"] <= window["lte"]]


T0 = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)


def detection(ip="192.168.50.20", kind="BRUTE_FORCE", at=T0):
    return {"detection_id": f"DET-{kind}-{at.isoformat()}", "source_ip": ip, "type": kind, "severity": "high", "timestamp": at.isoformat()}


def store_event(store, ip, at, **fields):
    doc = {"@timestamp": at.isoformat(), "source": {"ip": ip}, **event(**fields)}
    store.docs.setdefault("trapsig-events-2026.11.26", {})[f"e{len(store.docs.get('trapsig-events-2026.11.26', {}))}"] = doc


def test_cycle_decides_enforces_evaluates_and_learns(monkeypatch):
    monkeypatch.delenv("HARDENING_MODE", raising=False)
    store = FakeStore()
    agent = rl.HardeningAgent(store)
    made = asyncio.run(agent.step([detection()], now=T0))
    assert len(made) == 1
    decision = made[0]
    assert decision["context"] == "credential|it|new" and decision["status"] == "active"
    assert decision["reason"] and decision["means"] and decision["previous_action"] == "observe"
    posture = next(iter(store.docs[rl.POSTURE_INDEX].values()))
    assert posture["action"] == decision["enforced_action"] and posture["actions"] == list(rl.EFFECTS[decision["enforced_action"]])
    # A second cycle inside the window does not re-decide.
    assert asyncio.run(agent.step([detection(at=T0 + timedelta(seconds=30))], now=T0 + timedelta(seconds=60))) == []
    # Attacker succeeds during the window -> negative reward credited to the chosen arm.
    store_event(store, "192.168.50.20", T0 + timedelta(seconds=90), action="login_attempt", category="authentication", outcome="success")
    later = T0 + timedelta(seconds=rl.config()["window_seconds"] + 1)
    asyncio.run(agent.step([], now=later))
    evaluated = store.docs[rl.DECISIONS_INDEX][decision["decision_id"]]
    assert evaluated["status"] == "evaluated" and evaluated["outcome"]["harm_events"] == 1 and evaluated["outcome"]["reward"] < 0
    arm = store.docs[rl.AGENT_INDEX][rl.AGENT_DOC_ID]["posteriors"]["credential|it|new"][decision["action"]]
    assert arm["n"] == 1 and arm["beta"] > arm["alpha"]


def test_returning_source_gets_its_own_context_and_quiet_sources_are_released(monkeypatch):
    monkeypatch.setenv("HARDENING_ALLOWED_ACTIONS", "deny_auth")
    store = FakeStore()
    agent = rl.HardeningAgent(store)
    asyncio.run(agent.step([detection()], now=T0))
    window = rl.config()["window_seconds"]
    asyncio.run(agent.step([], now=T0 + timedelta(seconds=window + 1)))  # evaluate
    second = asyncio.run(agent.step([detection(at=T0 + timedelta(seconds=window + 5))], now=T0 + timedelta(seconds=window + 10)))
    assert second[0]["context"] == "credential|it|returning" and second[0]["changed"] is False
    quiet = T0 + timedelta(seconds=window + 10 + rl.config()["lookback_seconds"] + rl.config()["release_after_seconds"] + 60)
    released = asyncio.run(agent.step([], now=quiet))  # evaluates, then releases the quiet source
    released += asyncio.run(agent.step([], now=quiet + timedelta(seconds=rl.config()["release_after_seconds"] + 1)))
    assert any(item.get("released") for item in released)
    assert next(iter(store.docs[rl.POSTURE_INDEX].values()))["actions"] == []


def test_shadow_mode_never_enforces_and_credits_observe(monkeypatch):
    monkeypatch.setenv("HARDENING_MODE", "shadow")
    store = FakeStore()
    agent = rl.HardeningAgent(store)
    decision = asyncio.run(agent.step([detection()], now=T0))[0]
    assert decision["enforced_action"] == "observe" and "shadow mode" in decision["reason"]
    assert next(iter(store.docs[rl.POSTURE_INDEX].values()))["actions"] == []
    asyncio.run(agent.step([], now=T0 + timedelta(seconds=rl.config()["window_seconds"] + 1)))
    assert store.docs[rl.DECISIONS_INDEX][decision["decision_id"]]["outcome"]["credited_to"] == "observe"
    monkeypatch.setenv("HARDENING_MODE", "off")
    assert asyncio.run(rl.HardeningAgent(FakeStore()).step([detection()], now=T0)) == []


# ---- sensor enforcement ------------------------------------------------------------ #


def test_sensor_enforces_each_effect():
    import common.hardening as posture
    from common.plugin import PersonaContext
    from plugins.coap import CoAPPlugin, parse_message
    from plugins.ftp import FTPPlugin
    from plugins.modbus import ModbusPlugin

    persona = PersonaContext("p", "P", "generic", "V", "M", "1", "h", (("admin", "admin"),))
    ip = "192.168.50.20"
    try:
        posture._apply({ip: {"level": "locked", "actions": ["deny_auth", "read_only", "bogus"], "decision_id": "HRD-1"}})
        effects, decision = posture.hardening_for(ip)
        assert effects == {"deny_auth", "read_only"} and decision == "HRD-1"  # unknown effects ignored
        assert posture.posture_for(ip) == "locked" and posture.hardening_for("10.0.0.1") == (frozenset(), None)
        ftp = FTPPlugin(persona, {}).conversation((ip, 1))
        ftp.state["hardening"] = effects
        ftp.handle(b"USER admin\r\n")
        assert ftp.handle(b"PASS admin\r\n").data.startswith(b"530")  # valid creds refused
        modbus = ModbusPlugin(persona, {}).conversation((ip, 1))
        modbus.state["hardening"] = effects
        reply = modbus.handle(struct.pack("!HHHB", 1, 0, 6, 1) + struct.pack("!BHH", 6, 0, 5))
        assert reply.data[7] == 0x86 and reply.data[8] == 0x04 and reply.events[0]["modbus"]["hardening_blocked"]
        put = bytes([0x41, 3, 0, 1, 0xAA, 0xB1]) + b"a"
        assert parse_message(CoAPPlugin(persona, {"resources": {"/a": "1"}}).datagram(put, (ip, 1), effects).data)["code"] == "4.03"
        # Legacy level-only payloads still map to effects.
        posture._apply({ip: "locked"})
        assert posture.hardening_for(ip)[0] == {"tarpit", "deny_auth"}
    finally:
        posture._apply({})


def test_runtime_stamps_hardening_and_drops_udp(tmp_path):
    import json

    import common.hardening as posture
    from common.persona import parse_persona
    from common.runtime import ReflectionGuard, Telemetry, handle_datagram

    persona = parse_persona({"id": "rt", "name": "R", "device_type": "generic", "services": [{"plugin": "coap", "port": 5683}]})
    telemetry = Telemetry(persona, str(tmp_path / "e.jsonl"), "192.168.50.10")
    binding = persona.bindings()[0]
    sent = []

    class Sock:
        def sendto(self, data, client):
            sent.append(data)

    try:
        posture._apply({"192.168.50.20": {"level": "locked", "actions": ["drop_udp"], "decision_id": "HRD-9"}})
        get = bytes([0x41, 1, 0, 1, 0xAA, 0xB1]) + b"sensors"
        assert handle_datagram(get, Sock(), ("192.168.50.20", 1), binding, telemetry, ReflectionGuard()) is False
        record = json.loads((tmp_path / "e.jsonl").read_text())
        assert record["reply_suppressed"] == "hardening_drop_udp" and record["hardening"] == {"actions": ["drop_udp"], "decision_id": "HRD-9"}
        assert sent == []
    finally:
        posture._apply({})


def test_off_mode_releases_postures_left_by_an_enforce_run(monkeypatch):
    """Regression: a baseline arm (HARDENING_MODE=off) was silently hardened by a stale deny_auth posture."""
    monkeypatch.delenv("HARDENING_MODE", raising=False)
    store = FakeStore()
    asyncio.run(rl.HardeningAgent(store).step([detection()], now=T0))
    assert next(iter(store.docs[rl.POSTURE_INDEX].values()))["actions"]
    monkeypatch.setenv("HARDENING_MODE", "off")
    released = asyncio.run(rl.HardeningAgent(store).step([detection()], now=T0 + timedelta(seconds=5)))
    assert released and released[0]["released"]
    posture = next(iter(store.docs[rl.POSTURE_INDEX].values()))
    assert posture["actions"] == [] and posture["action"] == "observe"
    assert asyncio.run(rl.HardeningAgent(store).step([], now=T0 + timedelta(seconds=10))) == []  # idempotent
