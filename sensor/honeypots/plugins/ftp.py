"""FTP control-channel emulation (RFC 959) with **no data channel**.

Authentication against persona honey-credentials (plus optional anonymous),
navigation replies, and file-transfer intent are all recorded. Every data
connection command (PASV/EPSV/PORT/EPRT) and every transfer (LIST/RETR/STOR/...)
is refused with ``425``: the sensor never opens or connects a second socket, so
it cannot be used for FTP bounce scanning or as a file drop. Three failed logins
close the connection, like many embedded FTP daemons.
"""

from __future__ import annotations

from typing import Any

from common.plugin import Conversation, PluginConfigError, ProtocolPlugin, Reply, option, register

PRE_AUTH = {"USER", "PASS", "QUIT", "SYST", "FEAT", "AUTH", "HELP", "NOOP", "OPTS"}
DATA = {"PASV", "EPSV", "PORT", "EPRT", "LIST", "NLST", "MLSD", "RETR", "STOR", "APPE", "STOU"}


@register
class FTPPlugin(ProtocolPlugin):
    name = "ftp"
    protocol = "ftp"
    default_port = 2121
    interaction = "low"
    max_messages_limit = 128

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        known = {"banner", "allow_anonymous", "max_failures"}
        if set(options) - known:
            raise PluginConfigError(f"ftp: unknown options {sorted(set(options) - known)}")
        failures = option(options, "max_failures", int, 3, "ftp")
        if not 1 <= failures <= 10:
            raise PluginConfigError("ftp: max_failures must be 1..10")
        return {
            "banner": str(options.get("banner", "FTP server ready."))[:120].replace("\r", "").replace("\n", ""),
            "allow_anonymous": option(options, "allow_anonymous", bool, False, "ftp"),
            "max_failures": failures,
        }

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return FTPConversation(self, client)


class FTPConversation(Conversation):
    def greeting(self) -> Reply:
        return Reply(
            f"220 {self.plugin.options['banner']}\r\n".encode(), [{"category": "session", "type": "start", "action": "ftp_banner", "summary": "ftp connection"}]
        )

    def handle(self, message: bytes) -> Reply:
        line = message.decode("latin-1").strip()
        verb, _, argument = line.partition(" ")
        verb = verb.upper()[:8]
        argument = argument[:256]
        options = self.plugin.options
        authed = self.state.get("authenticated", False)
        details: dict[str, Any] = {
            "category": "network",
            "action": f"ftp_{verb.lower() or 'empty'}",
            "outcome": "unknown",
            "ftp": {"command": verb, "argument": argument or None},
        }
        close = False
        if verb == "USER":
            self.state["username"] = argument
            reply = "331 Password required."
        elif verb == "PASS":
            username = self.state.get("username")
            if username is None:
                reply = "503 Login with USER first."
            else:
                anonymous = options["allow_anonymous"] and username.lower() in {"anonymous", "ftp"}
                ok = (anonymous and "deny_auth" not in self.hardening) or self.accepts(username, argument)
                details.update(
                    category="authentication",
                    action="login_attempt",
                    outcome="success" if ok else "failure",
                    authentication={"username": username, "password": argument},
                )
                details["ftp"]["argument"] = None  # password lives only in authentication.*
                if ok:
                    self.state["authenticated"] = True
                    reply = "230 Login successful."
                else:
                    failures = self.state.get("failures", 0) + 1
                    self.state["failures"] = failures
                    close = failures >= options["max_failures"]
                    reply = "530 Login incorrect."
        elif verb == "QUIT":
            reply, close = "221 Goodbye.", True
        elif verb == "SYST":
            reply = "215 UNIX Type: L8"
        elif verb == "FEAT":
            reply = "211-Features:\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End"
        elif verb == "AUTH":
            reply = "502 TLS not available."
        elif verb in {"NOOP", "OPTS"}:
            reply = "200 OK."
        elif verb == "HELP":
            reply = "214 USER PASS PWD CWD TYPE SYST FEAT QUIT"
        elif not authed and verb not in PRE_AUTH:
            reply = "530 Please login with USER and PASS."
            details["outcome"] = "failure"
        elif verb == "PWD":
            reply = f'257 "{self.state.get("cwd", "/")}" is the current directory'
        elif verb == "CWD":
            self.state["cwd"] = argument if argument.startswith("/") else f"/{argument}"
            reply = "250 Directory successfully changed."
        elif verb == "TYPE":
            reply = "200 Switching to Binary mode." if argument.upper().startswith("I") else "200 Switching to ASCII mode."
        elif verb in DATA:
            reply = "425 Can't open data connection."
            details["outcome"] = "failure"
            details["ftp"]["data_channel_refused"] = True
        else:
            reply = "502 Command not implemented."
        details["ftp"]["reply_code"] = int(reply[:3])
        details["summary"] = f"ftp {verb} -> {reply[:3]}"
        return Reply((reply + "\r\n").encode(), [details], close=close)
