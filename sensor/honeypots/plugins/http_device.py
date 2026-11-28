"""Configurable HTTP device UI: a new web persona is TOML, not code.

Options declare a ``Server`` header, a login form path, and ``pages``: per path a
status, content type, body and whether authentication is required. Bodies may use
``$name``, ``$model``, ``$vendor``, ``$firmware``, ``$hostname`` placeholders
(``string.Template`` -- no format-string injection). Authentication uses persona
honey-credentials via Basic auth or a form POST that issues an expiring
in-memory session cookie (bounded store). One request per connection, using the
shared bounded HTTP reader.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
from http import HTTPStatus
from string import Template
from typing import Any

from common.plugin import Conversation, FrameError, PluginConfigError, ProtocolPlugin, Reply, option, register
from common.protocols import http_details
from common.server import HTTPRequestReadError, http_error_response, read_http_request

MAX_SESSIONS = 256
SESSION_TTL = 900.0


class SessionStore:
    def __init__(self, clock=time.monotonic) -> None:
        self._clock, self._lock, self._items = clock, threading.Lock(), {}

    def issue(self) -> str:
        token = secrets.token_hex(16)
        now = self._clock()
        with self._lock:
            self._items = {k: v for k, v in self._items.items() if v > now}
            if len(self._items) >= MAX_SESSIONS:
                self._items.pop(min(self._items, key=self._items.get))
            self._items[token] = now + SESSION_TTL
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            return self._items.get(token, 0) > self._clock()


@register
class HTTPDevicePlugin(ProtocolPlugin):
    name = "http-device"
    protocol = "http"
    default_port = 8088
    interaction = "low"
    max_messages_limit = 1

    @classmethod
    def validate_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        known = {"server", "realm", "login_path", "pages", "not_found_body"}
        if set(options) - known:
            raise PluginConfigError(f"http-device: unknown options {sorted(set(options) - known)}")
        pages = options.get("pages", {"/": {"body": "<html><title>$name</title><body>$model</body></html>"}})
        if not isinstance(pages, dict) or not pages or len(pages) > 64:
            raise PluginConfigError("http-device: pages must be a table of 1-64 entries")
        clean = {}
        for path, page in pages.items():
            if not (isinstance(path, str) and path.startswith("/") and isinstance(page, dict)):
                raise PluginConfigError("http-device: each page needs a '/path' key and a table value")
            status = page.get("status", 200)
            if status not in {s.value for s in HTTPStatus}:
                raise PluginConfigError(f"http-device: page {path} has invalid status")
            body = page.get("body", "")
            if not isinstance(body, str) or len(body) > 32_768:
                raise PluginConfigError(f"http-device: page {path} body must be a string ≤32 KiB")
            clean[path] = {
                "status": status,
                "body": body,
                "content_type": str(page.get("content_type", "text/html; charset=utf-8"))[:80],
                "auth": bool(page.get("auth", False)),
            }
        return {
            "server": str(options.get("server", "lighttpd/1.4.59"))[:80],
            "realm": str(options.get("realm", "Device"))[:64].replace('"', ""),
            "login_path": option(options, "login_path", str, "/login", "http-device"),
            "pages": clean,
            "not_found_body": str(options.get("not_found_body", "<html><body><h1>404 Not Found</h1></body></html>"))[:4096],
        }

    def __init__(self, persona, options=None) -> None:
        super().__init__(persona, options)
        self.sessions = SessionStore()
        self.variables = {"name": persona.name, "model": persona.model, "vendor": persona.vendor, "firmware": persona.firmware, "hostname": persona.hostname}

    def read_message(self, connection: socket.socket, conversation: Conversation) -> bytes | None:
        if conversation.state.get("done"):
            return None
        try:
            return read_http_request(connection)
        except HTTPRequestReadError as error:
            conversation.state["done"] = True
            connection.sendall(http_error_response(error))
            raise FrameError(error.reason) from error

    def conversation(self, client: tuple[str, int]) -> Conversation:
        return HTTPDeviceConversation(self, client)

    def render(self, body: str) -> bytes:
        return Template(body).safe_substitute(self.variables).encode()


def _cookie(header: str) -> str | None:
    for item in header.split(";"):
        key, separator, value = item.strip().partition("=")
        if separator and key == "sid":
            return value
    return None


class HTTPDeviceConversation(Conversation):
    def handle(self, message: bytes) -> Reply:
        self.state["done"] = True
        plugin: HTTPDevicePlugin = self.plugin  # type: ignore[assignment]
        request = http_details(message)
        options = plugin.options
        method, path = request["method"].upper()[:16], request["path"][:512]
        supplied = request["username"] is not None
        credential_ok = supplied and self.accepts(request["username"], request["password"])
        session_ok = plugin.sessions.valid(_cookie(request["cookie"]))
        extra_headers: list[str] = []
        if method == "POST" and path == options["login_path"]:
            if credential_ok:
                status, body = 302, b""
                extra_headers += [f"Set-Cookie: sid={plugin.sessions.issue()}; HttpOnly; Path=/", "Location: /"]
            else:
                status, body = 200, plugin.render("<html><body><p>Invalid username or password.</p></body></html>")
        elif path in options["pages"]:
            page = options["pages"][path]
            if page["auth"] and not (session_ok or credential_ok):
                status, body = 401, b"<html><body><h1>401 Unauthorized</h1></body></html>"
                extra_headers.append(f'WWW-Authenticate: Basic realm="{options["realm"]}"')
            else:
                status, body = page["status"], plugin.render(page["body"])
                extra_headers.append(f"Content-Type: {page['content_type']}")
        else:
            status, body = 404, options["not_found_body"].encode()
        reason = HTTPStatus(status).phrase
        headers = [f"HTTP/1.1 {status} {reason}", f"Server: {options['server']}", f"Content-Length: {len(body)}", "Connection: close", *extra_headers]
        if not any(h.startswith("Content-Type") for h in extra_headers):
            headers.append("Content-Type: text/html; charset=utf-8")
        response = ("\r\n".join(headers) + "\r\n\r\n").encode() + body
        details: dict[str, Any] = {
            "category": "authentication" if supplied else "web",
            "action": "login_attempt" if supplied else "request",
            "outcome": ("success" if credential_ok else "failure") if supplied else ("success" if status < 400 else "failure"),
            "summary": f"http {method} {path} -> {status}",
            "http": {"request": {"method": method}, "response": {"status_code": status}, "user_agent": request["user_agent"]},
            "url": {"path": path},
        }
        if supplied:
            details["authentication"] = {"username": request["username"], "password": request["password"]}
        return Reply(response, [details], close=True)
