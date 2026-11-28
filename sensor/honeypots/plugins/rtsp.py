"""RTSP/1.0 camera control-plane emulation (RFC 2326). No media is ever sent.

OPTIONS → Public methods; DESCRIBE → 401 with a Basic challenge until valid
honey-credentials are supplied, then SDP for configured stream paths (404
otherwise); SETUP → 461 Unsupported Transport; PLAY/PAUSE/RECORD → 455;
TEARDOWN → 200. Requests are bounded to 8 KiB of headers and 4 KiB of body.
"""

from __future__ import annotations

import base64
import binascii
import socket
from typing import Any
from urllib.parse import urlsplit

from common.plugin import Conversation, FrameError, PluginConfigError, ProtocolPlugin, Reply, register

MAX_HEADER = 8192
MAX_BODY = 4096


def parse_request(raw: bytes) -> dict[str, Any]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) != 3 or not parts[2].startswith("RTSP/"):
        raise FrameError("invalid RTSP request line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    username = password = None
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("basic "):
        try:
            username, password = base64.b64decode(authorization[6:], validate=True).decode("utf-8").split(":", 1)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    uri = parts[1]
    return {
        "method": parts[0].upper()[:16],
        "uri": uri[:512],
        "path": (urlsplit(uri).path or "/")[:256],
        "version": parts[2],
        "cseq": headers.get("cseq", "0")[:16],
        "user_agent": headers.get("user-agent"),
        "transport": headers.get("transport"),
        "auth_scheme": authorization.split(" ", 1)[0].lower() if authorization else None,
        "username": username,
        "password": password,
        "body_length": len(body),
    }


@register
class RTSPPlugin(ProtocolPlugin):
    name = "rtsp"
    protocol = "rtsp"
    default_port = 8554
    interaction = "low"
    max_messages_limit = 32

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        known = {"streams", "server", "realm"}
        if set(options) - known:
            raise PluginConfigError(f"rtsp: unknown options {sorted(set(options) - known)}")
        streams = options.get("streams", ["/live/ch0", "/live/ch1"])
        if not isinstance(streams, list) or not streams or not all(isinstance(s, str) and s.startswith("/") and len(s) <= 128 for s in streams):
            raise PluginConfigError("rtsp: streams must be a list of paths starting with '/'")
        return {"streams": streams, "server": str(options.get("server", "RTSP Server/1.0"))[:80], "realm": str(options.get("realm", "IP Camera"))[:64]}

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        connection.settimeout(self.read_timeout)
        data = bytearray()
        try:
            while b"\r\n\r\n" not in data:
                if len(data) >= MAX_HEADER:
                    raise FrameError("header too large")
                chunk = connection.recv(min(2048, MAX_HEADER - len(data)))
                if not chunk:
                    return None if not data else bytes(data)
                data.extend(chunk)
            head, _, rest = bytes(data).partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                name, colon, value = line.partition(b":")
                if colon and name.strip().lower() == b"content-length":
                    if not value.strip().isdigit():
                        raise FrameError("bad content-length")
                    length = int(value.strip())
            if length > MAX_BODY:
                raise FrameError("body too large")
            body = bytearray(rest[:length])
            while len(body) < length:
                chunk = connection.recv(length - len(body))
                if not chunk:
                    break
                body.extend(chunk)
        except socket.timeout as exc:
            raise FrameError("read timeout") from exc
        return head + b"\r\n\r\n" + bytes(body)

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return RTSPConversation(self, client)


class RTSPConversation(Conversation):
    def handle(self, message: bytes) -> Reply:
        request = parse_request(message)
        plugin = self.plugin
        method, path = request["method"], request["path"]
        authed = self.state.get("authenticated") or self.accepts(request["username"], request["password"])
        if authed:
            self.state["authenticated"] = True
        headers: list[str] = [f"CSeq: {request['cseq']}", f"Server: {plugin.options['server']}"]
        body = b""
        if method == "OPTIONS":
            status = "200 OK"
            headers.append("Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER")
        elif method == "DESCRIBE":
            if not authed:
                status = "401 Unauthorized"
                headers.append(f'WWW-Authenticate: Basic realm="{plugin.options["realm"]}"')
            elif path in plugin.options["streams"]:
                status = "200 OK"
                body = (
                    "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n"
                    f"s={plugin.persona.model or 'Stream'}\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\n"
                    "a=rtpmap:96 H264/90000\r\na=control:trackID=1\r\n"
                ).encode()
                headers += ["Content-Type: application/sdp", f"Content-Base: {request['uri'].rstrip('/')}/"]
            else:
                status = "404 Not Found"
        elif method == "SETUP":
            status = "461 Unsupported Transport" if authed else "401 Unauthorized"
            if not authed:
                headers.append(f'WWW-Authenticate: Basic realm="{plugin.options["realm"]}"')
        elif method in {"PLAY", "PAUSE", "RECORD"}:
            status = "455 Method Not Valid in This State"
        elif method in {"TEARDOWN", "GET_PARAMETER"}:
            status = "200 OK"
        else:
            status = "501 Not Implemented"
        if body:
            headers.append(f"Content-Length: {len(body)}")
        response = (f"RTSP/1.0 {status}\r\n" + "\r\n".join(headers) + "\r\n\r\n").encode() + body
        rtsp = {key: request[key] for key in ("method", "uri", "path", "cseq", "auth_scheme", "transport", "body_length")}
        rtsp["status_code"] = int(status.split()[0])
        details: dict[str, Any] = {
            "category": "authentication" if request["username"] else "network",
            "action": "login_attempt" if request["username"] else f"rtsp_{method.lower()}",
            "outcome": ("success" if authed else "failure") if request["username"] else ("success" if rtsp["status_code"] < 400 else "failure"),
            "summary": f"rtsp {method} {path} -> {rtsp['status_code']}",
            "rtsp": rtsp,
            "http": {"user_agent": request["user_agent"]} if request["user_agent"] else None,
        }
        if request["username"]:
            details["authentication"] = {"username": request["username"], "password": request["password"]}
        return Reply(response, [details], close=method == "TEARDOWN")
