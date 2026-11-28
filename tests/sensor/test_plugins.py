"""Protocol plugins: framing, replies, bounds and emitted telemetry (no sockets)."""

import base64
import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

from common.community_id import community_id  # noqa: E402
from common.persona import PersonaError, load_directory, parse_persona  # noqa: E402
from common.plugin import REGISTRY, FrameError, PersonaContext, PluginConfigError  # noqa: E402
from plugins.coap import CoAPPlugin, parse_message  # noqa: E402
from plugins.dns import DNSPlugin, parse_query  # noqa: E402
from plugins.ftp import FTPPlugin  # noqa: E402
from plugins.http_device import HTTPDevicePlugin  # noqa: E402
from plugins.modbus import ModbusPlugin  # noqa: E402
from plugins.rtsp import RTSPPlugin  # noqa: E402
from plugins.ssdp import SSDPPlugin  # noqa: E402

PERSONA = PersonaContext("test-dev", "Test Device", "generic", "Acme", "AX-1", "1.2.3", "ax1", (("admin", "admin"),))
CLIENT = ("192.168.50.20", 40000)


# ---- Community ID ------------------------------------------------------------ #


def test_community_id_matches_spec_vector_and_is_direction_independent():
    forward = community_id("128.232.110.120", 34855, "66.35.250.204", 80, "tcp")
    assert forward == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert community_id("66.35.250.204", 80, "128.232.110.120", 34855, "tcp") == forward
    assert community_id("1.2.3.4", 1, "::1", 2, "tcp") is None  # mixed families
    assert community_id("x", 1, "1.2.3.4", 2, "tcp") is None


# ---- Persona validation -------------------------------------------------------- #


def test_every_shipped_persona_is_valid_and_binds():
    personas = load_directory("sensor/honeypots/personas")
    assert len(personas) >= 6
    for persona in personas.values():
        assert persona.bindings()
        assert persona.summary()["content_sha256"]


def _persona(**overrides):
    data = {"id": "p-one", "name": "P", "device_type": "generic", "services": [{"plugin": "ftp", "port": 2121}]}
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"services": [{"plugin": "ftp", "port": 21}]}, "privileged"),
        ({"services": [{"plugin": "nope", "port": 2121}]}, "unknown plugin"),
        ({"services": [{"plugin": "ftp", "port": 2121}, {"plugin": "rtsp", "name": "xx", "port": 2121}]}, "already used"),
        ({"services": [{"plugin": "ftp", "port": 2121, "public_port": 21}, {"plugin": "ftp", "name": "f2", "port": 2122, "public_port": 21}]}, "already used"),
        ({"services": [{"plugin": "ftp", "port": 2121, "options": {"bogus": 1}}]}, "unknown options"),
        ({"device_type": "toaster"}, "device_type"),
        ({"id": "Bad_ID"}, "kebab"),
        ({"surprise": True}, "unknown top-level"),
        ({"services": []}, "at least one"),
        ({"interaction": {"max_messages": 0}}, "max_messages"),
        ({"credentials": {"accept": [["only-user"]]}}, "credentials"),
    ],
)
def test_invalid_personas_are_rejected_with_a_useful_message(overrides, message):
    with pytest.raises(PersonaError, match=message):
        parse_persona(_persona(**overrides))


def test_udp_and_tcp_may_share_a_port_number():
    persona = parse_persona(_persona(services=[{"plugin": "dns", "port": 5353}, {"plugin": "ftp", "port": 5353}]))
    assert {s.plugin for s in persona.services} == {"dns", "ftp"}


def test_every_registered_plugin_declares_its_contract():
    for name, cls in REGISTRY.items():
        assert cls.name == name and cls.transport in {"tcp", "udp"} and cls.interaction in {"low", "medium"}
        assert 1024 <= cls.default_port <= 65535


# ---- Modbus ------------------------------------------------------------------- #


def mbap(transaction, unit, pdu):
    return struct.pack("!HHHB", transaction, 0, len(pdu) + 1, unit) + pdu


@pytest.fixture
def modbus():
    plugin = ModbusPlugin(PERSONA, {"unit_id": 1, "holding_registers": [10, 20, 30, 40]})
    return plugin.conversation(CLIENT)


def test_modbus_read_holding_registers(modbus):
    reply = modbus.handle(mbap(7, 1, struct.pack("!BHH", 3, 1, 2)))
    assert reply.data == mbap(7, 1, bytes([3, 4]) + struct.pack("!HH", 20, 30))
    event = reply.events[0]
    assert event["modbus"]["function_code"] == 3 and event["modbus"]["address"] == 1 and event["modbus"]["write"] is False


def test_modbus_write_is_connection_local_and_read_back(modbus):
    modbus.handle(mbap(1, 1, struct.pack("!BHH", 6, 0, 999)))
    assert modbus.handle(mbap(2, 1, struct.pack("!BHH", 3, 0, 1))).data.endswith(struct.pack("!H", 999))
    fresh = ModbusPlugin(PERSONA, {"holding_registers": [10, 20, 30, 40]}).conversation(CLIENT)
    assert fresh.handle(mbap(3, 1, struct.pack("!BHH", 3, 0, 1))).data.endswith(struct.pack("!H", 10))


@pytest.mark.parametrize(
    "pdu,code",
    [
        (struct.pack("!BHH", 3, 3, 5), 2),  # beyond map
        (struct.pack("!BHH", 3, 0, 0), 3),  # zero quantity
        (bytes([0x2B, 0x0D]), 1),  # MEI other than 14
        (bytes([0x08, 0, 0]), 1),  # diagnostics unsupported
        (struct.pack("!BHH", 5, 0, 0x1234), 3),  # invalid coil value
    ],
)
def test_modbus_exceptions(modbus, pdu, code):
    reply = modbus.handle(mbap(9, 1, pdu))
    assert reply.data[7] == pdu[0] | 0x80 and reply.data[8] == code
    assert reply.events[0]["modbus"]["exception_code"] == code


def test_modbus_foreign_unit_gets_gateway_exception(modbus):
    assert modbus.handle(mbap(1, 9, struct.pack("!BHH", 3, 0, 1))).data[8] == 0x0B


def test_modbus_device_identification_reveals_persona(modbus):
    reply = modbus.handle(mbap(4, 1, bytes([0x2B, 0x0E, 0x01, 0x00])))
    assert b"Acme" in reply.data and b"AX-1" in reply.data and b"1.2.3" in reply.data


def test_modbus_framing_rejects_bad_mbap():
    plugin = ModbusPlugin(PERSONA, {})
    left, right = socket.socketpair()
    try:
        left.sendall(struct.pack("!HHHB", 1, 7, 2, 1) + b"\x03")
        with pytest.raises(FrameError):
            plugin.read_message(right, plugin.conversation(CLIENT))
    finally:
        left.close()
        right.close()
    left, right = socket.socketpair()  # the runtime closes a connection after a framing error
    try:
        left.sendall(struct.pack("!HHHB", 1, 0, 6, 1) + struct.pack("!BHH", 3, 0, 1))
        assert plugin.read_message(right, plugin.conversation(CLIENT)).endswith(struct.pack("!BHH", 3, 0, 1))
    finally:
        left.close()
        right.close()


def test_modbus_rejects_invalid_options():
    with pytest.raises(PluginConfigError):
        ModbusPlugin(PERSONA, {"holding_registers": [70000]})
    with pytest.raises(PluginConfigError):
        ModbusPlugin(PERSONA, {"unit_id": True})


# ---- CoAP ---------------------------------------------------------------------- #


def coap_get(path_segments, mtype=0, message_id=0x1234, token=b"\xab"):
    options, previous = b"", 0
    for segment in path_segments:
        delta = 11 - previous
        options += bytes([(delta << 4) | len(segment)]) + segment
        previous = 11
    return bytes([(1 << 6) | (mtype << 4) | len(token), 1]) + struct.pack("!H", message_id) + token + options


def test_coap_well_known_core_and_ack_semantics():
    plugin = CoAPPlugin(PERSONA, {"resources": {"/a": "1", "/b": "2"}})
    reply = plugin.datagram(coap_get([b".well-known", b"core"]), CLIENT)
    response = parse_message(reply.data)
    assert response["type"] == "ACK" and response["message_id"] == 0x1234 and response["code"] == "2.05"
    assert b"</a>" in reply.data and b"</b>" in reply.data
    assert reply.events[0]["coap"]["uri_path"] == "/.well-known/core"


def test_coap_resource_unknown_and_state_change():
    plugin = CoAPPlugin(PERSONA, {"resources": {"/a": "1"}, "read_only": True})
    assert parse_message(plugin.datagram(coap_get([b"a"]), CLIENT).data)["code"] == "2.05"
    assert parse_message(plugin.datagram(coap_get([b"zz"]), CLIENT).data)["code"] == "4.04"
    put = bytearray(coap_get([b"a"]))
    put[1] = 3
    reply = plugin.datagram(bytes(put), CLIENT)
    assert parse_message(reply.data)["code"] == "4.01"
    assert reply.events[0]["coap"]["state_change"] is True


def test_coap_non_request_gets_non_response_and_malformed_is_silent():
    plugin = CoAPPlugin(PERSONA, {})
    assert parse_message(plugin.datagram(coap_get([b"sensors", b"temperature"], mtype=1), CLIENT).data)["type"] == "NON"
    reply = plugin.datagram(b"\x00\x01", CLIENT)
    assert reply.data == b"" and reply.events[0]["action"] == "malformed"


# ---- FTP ----------------------------------------------------------------------- #


def ftp_session(options=None):
    conversation = FTPPlugin(PERSONA, options or {}).conversation(CLIENT)
    assert conversation.greeting().data.startswith(b"220 ")
    return conversation


def test_ftp_login_success_and_no_data_channel():
    conv = ftp_session()
    assert conv.handle(b"LIST\r\n").data.startswith(b"530")  # pre-auth
    conv.handle(b"USER admin\r\n")
    reply = conv.handle(b"PASS admin\r\n")
    assert reply.data.startswith(b"230")
    assert reply.events[0]["authentication"] == {"username": "admin", "password": "admin"}
    assert reply.events[0]["ftp"]["argument"] is None  # password not duplicated
    for command in (b"PASV\r\n", b"PORT 10,0,0,1,4,1\r\n", b"STOR x.sh\r\n", b"RETR /etc/passwd\r\n"):
        reply = conv.handle(command)
        assert reply.data.startswith(b"425") and reply.events[0]["ftp"]["data_channel_refused"]


def test_ftp_closes_after_repeated_failures_and_supports_anonymous():
    conv = ftp_session({"max_failures": 2})
    conv.handle(b"USER root\r\n")
    assert not conv.handle(b"PASS a\r\n").close
    assert conv.handle(b"PASS b\r\n").close
    anon = ftp_session({"allow_anonymous": True})
    anon.handle(b"USER anonymous\r\n")
    assert anon.handle(b"PASS x@y\r\n").data.startswith(b"230")


# ---- RTSP ---------------------------------------------------------------------- #


def rtsp(method, uri, cseq=1, auth=None):
    lines = [f"{method} {uri} RTSP/1.0", f"CSeq: {cseq}", "User-Agent: LibVLC/3.0"]
    if auth:
        lines.append("Authorization: Basic " + base64.b64encode(auth.encode()).decode())
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def test_rtsp_describe_requires_auth_then_returns_sdp():
    conv = RTSPPlugin(PERSONA, {"streams": ["/live"]}).conversation(CLIENT)
    assert conv.handle(rtsp("OPTIONS", "rtsp://h/")).data.startswith(b"RTSP/1.0 200")
    challenge = conv.handle(rtsp("DESCRIBE", "rtsp://h/live", 2))
    assert challenge.data.startswith(b"RTSP/1.0 401") and b"WWW-Authenticate" in challenge.data
    ok = conv.handle(rtsp("DESCRIBE", "rtsp://h/live", 3, "admin:admin"))
    assert ok.data.startswith(b"RTSP/1.0 200") and b"m=video" in ok.data and b"CSeq: 3" in ok.data
    assert ok.events[0]["category"] == "authentication" and ok.events[0]["outcome"] == "success"
    assert conv.handle(rtsp("DESCRIBE", "rtsp://h/other", 4)).data.startswith(b"RTSP/1.0 404")
    assert conv.handle(rtsp("SETUP", "rtsp://h/live/trackID=1", 5)).data.startswith(b"RTSP/1.0 461")


def test_rtsp_rejects_non_rtsp_request_line():
    conv = RTSPPlugin(PERSONA, {}).conversation(CLIENT)
    with pytest.raises(FrameError):
        conv.handle(b"GET / HTTP/1.1\r\n\r\n")


# ---- SSDP / DNS ------------------------------------------------------------------ #


MSEARCH = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'


def test_ssdp_msearch_reply_and_notify_silence():
    plugin = SSDPPlugin(PERSONA, {"location_host": "192.168.50.10", "location_port": 5000})
    reply = plugin.datagram(MSEARCH, CLIENT)
    assert b"LOCATION: http://192.168.50.10:5000/rootDesc.xml" in reply.data
    assert len(reply.data) <= 10 * len(MSEARCH)
    assert plugin.datagram(b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n\r\n", CLIENT).data == b""


def dns_query(name, qtype=1, qclass=1, rd=True):
    header = struct.pack("!HHHHHH", 0xBEEF, 0x0100 if rd else 0, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + labels + struct.pack("!HH", qtype, qclass)


def rcode(data):
    return struct.unpack("!H", data[2:4])[0] & 0xF


def test_dns_is_authoritative_only_and_never_recursive():
    plugin = DNSPlugin(PERSONA, {"zone": "lan", "records": {"gw.lan": "192.168.50.1"}, "version": "dnsmasq-2.80"})
    answer = plugin.datagram(dns_query("gw.lan"), CLIENT)
    assert rcode(answer.data) == 0 and answer.data.endswith(bytes([192, 168, 50, 1]))
    assert struct.unpack("!H", answer.data[2:4])[0] & 0x0080 == 0  # RA=0
    assert rcode(plugin.datagram(dns_query("example.com"), CLIENT).data) == 5
    assert rcode(plugin.datagram(dns_query("missing.lan"), CLIENT).data) == 3
    assert rcode(plugin.datagram(dns_query("gw.lan", qtype=255), CLIENT).data) == 5
    version = plugin.datagram(dns_query("version.bind", qtype=16, qclass=3), CLIENT)
    assert b"dnsmasq-2.80" in version.data
    assert parse_query(dns_query("gw.lan"))["qname"] == "gw.lan"


def test_dns_rejects_compression_and_garbage():
    plugin = DNSPlugin(PERSONA, {})
    assert plugin.datagram(b"\x00" * 5, CLIENT).data == b""
    pointer = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    assert plugin.datagram(pointer, CLIENT).events[0]["action"] == "malformed"


# ---- HTTP device ------------------------------------------------------------------ #


def http(method, path, headers=(), body=b""):
    lines = [f"{method} {path} HTTP/1.1", "Host: x", *headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def test_http_device_pages_auth_cookie_and_templates():
    plugin = HTTPDevicePlugin(PERSONA, {"pages": {"/": {"body": "<h1>$model $firmware</h1>"}, "/secret": {"auth": True, "body": "ok"}}})
    assert b"<h1>AX-1 1.2.3</h1>" in plugin.conversation(CLIENT).handle(http("GET", "/")).data
    assert plugin.conversation(CLIENT).handle(http("GET", "/secret")).data.startswith(b"HTTP/1.1 401")
    basic = "Authorization: Basic " + base64.b64encode(b"admin:admin").decode()
    assert plugin.conversation(CLIENT).handle(http("GET", "/secret", [basic])).data.startswith(b"HTTP/1.1 200")
    login = plugin.conversation(CLIENT).handle(http("POST", "/login", ["Content-Type: application/x-www-form-urlencoded"], b"username=admin&password=admin"))
    assert login.data.startswith(b"HTTP/1.1 302")
    cookie = login.data.split(b"Set-Cookie: ")[1].split(b";")[0].decode()
    assert plugin.conversation(CLIENT).handle(http("GET", "/secret", [f"Cookie: {cookie}"])).data.startswith(b"HTTP/1.1 200")
    assert plugin.conversation(CLIENT).handle(http("GET", "/nope")).data.startswith(b"HTTP/1.1 404")
    failed = plugin.conversation(CLIENT).handle(http("POST", "/login", [], b"username=admin&password=bad"))
    assert failed.events[0]["outcome"] == "failure" and failed.events[0]["category"] == "authentication"


def test_http_device_template_cannot_reach_python_attributes():
    plugin = HTTPDevicePlugin(PERSONA, {"pages": {"/": {"body": "${name.__class__} {name.__class__}"}}})
    body = plugin.conversation(CLIENT).handle(http("GET", "/")).data
    assert b"__class__" in body and b"<class" not in body
