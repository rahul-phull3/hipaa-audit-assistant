"""Pure-ASGI middleware: API key, request body limit and security headers.

Written against the ASGI interface directly (not ``BaseHTTPMiddleware``) so they do not buffer bodies or interfere with
background tasks.
"""

from __future__ import annotations

import hmac
import json
import logging
from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger(__name__)

PUBLIC_API_PATHS = frozenset({"/api/health"})

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


class BodyTooLarge(Exception):
    """Raised from ``receive`` when a request body goes over the limit while it is being read."""


def error_body(code: str, message: str) -> bytes:
    return json.dumps({"error": {"code": code, "message": message}}).encode("utf-8")


async def send_json_error(
    send: Send, status: int, code: str, message: str, headers: Iterable[tuple[bytes, bytes]] = ()
) -> None:
    body = error_body(code, message)
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), *headers],
        }
    )
    await send({"type": "http.response.body", "body": body})


class ErrorBoundaryMiddleware:
    """Turn an unexpected exception into a generic JSON 500.

    Starlette's own handler sits outside every middleware, so its response would miss the security and CORS headers; this one
    sits inside them. The traceback goes to the log and never to the client.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            log.exception("unhandled error on %s %s", scope.get("method"), scope.get("path"))
            if started:  # the response is already on its way; the server has to close the connection
                raise
            await send_json_error(send, 500, "internal_error", "Something went wrong on the server.")


def host_name(host_header: str) -> str:
    """The name in a Host header without its port, lower case: ``Localhost:8000`` -> ``localhost``, ``[::1]:8000`` -> ``[::1]``."""
    host = host_header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    return host.split(":", 1)[0]


class AllowedHostsMiddleware:
    """Answer only to the host names the server is meant to be reached by.

    A web page can point its own domain at 127.0.0.1 (DNS rebinding) and then talk to a server on localhost as if it were its
    own site, so the browser's same-origin rules do not stop it. The Host header still names the attacker's domain, which is
    how this check turns the request away.
    """

    def __init__(self, app: ASGIApp, hosts: Iterable[str]) -> None:
        self.app = app
        self.hosts = frozenset(h.strip().lower() for h in hosts if h.strip())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.hosts or scope["type"] != "http":
            return await self.app(scope, receive, send)
        supplied = host_name(dict(scope["headers"]).get(b"host", b"").decode("latin-1"))
        if supplied not in self.hosts:
            return await send_json_error(
                send,
                400,
                "invalid_host",
                "This server does not answer to that host name. Open it by the address it was started on, or add the name to HIPAA_AUDIT_ALLOWED_HOSTS.",
            )
        await self.app(scope, receive, send)


class OriginCheckMiddleware:
    """Refuse requests that change something when a browser sends them from another site.

    A page on any site can make a visitor's browser POST a form to a server on localhost without a CORS preflight, which
    would queue reviews (and spend model credits) on a server that has no API key. Browsers always say where such a request
    came from (``Origin``, ``Sec-Fetch-Site``), so a request from a site that is neither this server's own origin nor a listed
    CORS origin is refused. A request with neither header is not a browser's (curl, a script, another server) and passes.
    """

    CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def __init__(self, app: ASGIApp, allowed_origins: Iterable[str] = ()) -> None:
        self.app = app
        self.allowed = frozenset(o.strip().rstrip("/").lower() for o in allowed_origins if o.strip())

    def _allowed(self, headers: dict[bytes, bytes]) -> bool:
        origin = headers.get(b"origin", b"").decode("latin-1").strip().lower()
        if origin:
            host = headers.get(b"host", b"").decode("latin-1").strip().lower()
            same_site_as_host = bool(host) and urlsplit(origin).netloc == host
            return same_site_as_host or origin in self.allowed
        fetch_site = headers.get(b"sec-fetch-site", b"").decode("latin-1").strip().lower()
        return fetch_site in ("", "same-origin", "none")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in self.CHANGING or not scope["path"].startswith("/api/"):
            return await self.app(scope, receive, send)
        if not self._allowed(dict(scope["headers"])):
            return await send_json_error(
                send,
                403,
                "forbidden_origin",
                "This request came from a site that is not allowed to change anything here.",
            )
        await self.app(scope, receive, send)


class ApiKeyMiddleware:
    """Require ``X-API-Key`` on every /api request except health checks and CORS preflights."""

    def __init__(self, app: ASGIApp, api_key: str | None) -> None:
        self.app = app
        self._key = api_key.encode("utf-8") if api_key else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._key is None or scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        if not path.startswith("/api/") or path in PUBLIC_API_PATHS or scope["method"] == "OPTIONS":
            return await self.app(scope, receive, send)
        supplied = dict(scope["headers"]).get(b"x-api-key", b"")
        if not hmac.compare_digest(supplied, self._key):
            return await send_json_error(send, 401, "unauthorized", "A valid X-API-Key header is required.")
        await self.app(scope, receive, send)


class BodyLimitMiddleware:
    """Reject request bodies over ``max_bytes`` early (by Content-Length) and while streaming (chunked uploads)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    return await send_json_error(send, 413, "too_large", "The upload is larger than the allowed size.")
            except ValueError:
                return await send_json_error(send, 400, "bad_request", "Invalid Content-Length header.")
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyTooLarge()
            return message

        await self.app(scope, limited_receive, send)


class SecurityHeadersMiddleware:
    """Headers every response should carry. API responses are never cached; the UI gets a strict content security policy."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        is_api = scope["path"].startswith("/api/")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                managed = _MANAGED | {b"cache-control"} if is_api else _MANAGED
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in managed]
                headers += [
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                ]
                if is_api:
                    headers.append((b"cache-control", b"no-store"))
                else:
                    headers.append((b"content-security-policy", CONTENT_SECURITY_POLICY.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


_MANAGED = frozenset({b"x-content-type-options", b"referrer-policy", b"x-frame-options", b"content-security-policy"})
