"""Security headers + CORS for the dashboard.

The dashboard previously shipped with no `Content-Security-Policy`, no
`X-Frame-Options`, no CORS policy at all (any origin's JS could be blocked
or allowed only by the browser's default same-origin behavior — fine until
someone adds a CORS header carelessly later with no allow-list to bound it),
and no anti-CSRF signal on state-changing requests.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from nexus.foundation.config import config

DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB — comfortably above any real
# login/config/scan/agent-run JSON payload this API expects.


class _RequestBodyTooLarge(Exception):
    """Internal signal only: raised from the wrapped ASGI `receive()` once a
    streamed request body crosses MaxBodySizeMiddleware's cap, so downstream
    body-parsing code (FastAPI's `payload: dict` dependency, in particular)
    is interrupted instead of buffering the rest of an oversized payload."""


class MaxBodySizeMiddleware:
    """Reject request bodies larger than `max_body_size` before any route
    handler, dependency, or auth check ever runs.

    FastAPI resolves a `payload: dict` parameter (used by /api/auth/login,
    /api/config, /api/scan/start, /api/agent/run) via Starlette's dependency
    injection, which fully buffers and JSON-decodes the request body BEFORE
    the route body executes — i.e. before `_require_token()` gets a chance
    to reject an unauthenticated caller. With no cap anywhere (no ASGI
    server limit, no middleware), a fully unauthenticated client could POST
    an arbitrarily large JSON body to any of those routes and force this
    process to buffer/decode it all in memory first — a DoS reachable
    without any credentials.

    Implemented as a plain ASGI callable (not BaseHTTPMiddleware) wrapping
    `receive()` so the body is measured as it streams in, rather than fully
    read into memory here just to measure it. Must be the OUTERMOST
    middleware — registered last in `install_middleware`, since Starlette
    treats the most-recently-added middleware as outermost — so oversized
    bodies are rejected before routing/dependency-injection ever touches
    them, and before any other middleware does its own body handling.
    """

    def __init__(self, app: ASGIApp, max_body_size: int = DEFAULT_MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast path: a well-formed Content-Length lets us reject before
        # reading a single byte of body.
        for name, value in scope.get("headers") or ():
            if name == b"content-length":
                try:
                    if int(value) > self.max_body_size:
                        await _send_413(send)
                        return
                except ValueError:
                    pass
                break

        total = 0

        async def guarded_receive() -> Message:
            nonlocal total
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body") or b"")
                if total > self.max_body_size:
                    raise _RequestBodyTooLarge()
            return message

        response_started = False

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, guarded_receive, tracking_send)
        except _RequestBodyTooLarge:
            if not response_started:
                await _send_413(send)


async def _send_413(send: Send) -> None:
    body = b'{"detail":"Request body too large"}'
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("latin-1")),
        ],
    })
    await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def get_cors_origins() -> list[str]:
    """Explicit allow-list, never a wildcard. Empty means "no cross-origin
    JS access" (same-origin requests don't need CORS headers at all, so an
    empty list is a safe, restrictive default, not a broken one)."""
    raw = os.environ.get("NEXUS_DASHBOARD_CORS_ORIGINS", "")
    if raw.strip():
        return [origin.strip() for origin in raw.split(",") if origin.strip()]
    if config.is_production:
        return []
    return ["http://127.0.0.1:8765", "http://localhost:8765"]


def install_middleware(app: FastAPI) -> None:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(SecurityHeadersMiddleware)

    origins = get_cors_origins()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
            max_age=600,
        )

    max_body_size = int(os.environ.get("NEXUS_DASHBOARD_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES)))
    # Added last so it becomes the OUTERMOST middleware (see
    # MaxBodySizeMiddleware's docstring) — it must see and reject an
    # oversized request before anything else, including CORS and the
    # security-headers middleware, ever touches it.
    app.add_middleware(MaxBodySizeMiddleware, max_body_size=max_body_size)


CSRF_HEADER = "X-Requested-With"
CSRF_HEADER_VALUE = "NEXUS-Dashboard"


def require_same_origin_signal(request: Request) -> None:
    """Lightweight CSRF defense for the dashboard's Bearer-token JSON API.

    A cross-site <form> POST or <img>/<script> "CSRF" trick can't set a
    custom header, so requiring one on every state-changing request blocks
    that class of attack without needing a stateful CSRF token — a classic,
    well-established mitigation for token-authenticated JSON APIs (as
    opposed to cookie-authenticated ones, where this alone isn't sufficient
    and a real CSRF token is needed; this dashboard uses a bearer token, not
    a cookie, for its actual auth decision).
    """
    from fastapi import HTTPException

    if request.headers.get(CSRF_HEADER) != CSRF_HEADER_VALUE:
        raise HTTPException(status_code=403, detail=f"Missing or invalid {CSRF_HEADER} header")
