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

from nexus.foundation.config import config


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
