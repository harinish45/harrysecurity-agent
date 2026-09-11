"""Scheme-validated, redirect-safe HTTP(S) fetch.

``urllib.request.urlopen()`` will happily follow ``file://``, ``ftp://``, and
other non-HTTP schemes — if a URL built from attacker-influenced input (a
scan target, a redirect Location header) ever reaches it unchecked, that's an
arbitrary local file read or protocol-smuggling primitive (bandit B310).
``safe_urlopen()`` is the one place in the codebase that calls
``urllib.request.urlopen()``/an opener built from it; every tool that used to
call ``urlopen`` directly now calls this instead, so the scheme check lives
in exactly one place rather than being repeated (or forgotten) per call site.

``ScopeGuard.validate(target)`` is called once, by ``ToolExecutor``, against
the mission's *original* target string before a tool ever runs. That does
nothing to stop a genuinely in-scope request from being redirected — via a
plain 30x ``Location`` header the target itself controls — to an
out-of-scope or internal host (the classic SSRF-via-redirect pivot to a
cloud-metadata endpoint like ``169.254.169.254``, or simply to a different
host the operator never authorised). ``urllib`` auto-follows redirects with
zero re-validation of each new hop. ``safe_urlopen()`` closes that gap
centrally, for every one of the ~280 tool files that call it, by building an
opener with a custom ``HTTPRedirectHandler`` that re-runs the exact same
``ScopeGuard.validate()`` check against every redirect target before
following it — the identical check the original target already had to pass,
so behaviour stays consistent with whatever scope the operator configured
(a broad ``NEXUS_ALLOWED_TARGETS=0.0.0.0/0`` permits a redirect anywhere,
same as it permits any initial target; a narrow scope blocks a redirect
outside it, same as it would block that host as an initial target).
"""
from __future__ import annotations

import ssl
import urllib.request
from typing import Any

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_REDIRECTS = 5


class UnsupportedSchemeError(ValueError):
    pass


class SSRFBlockedError(ValueError):
    """A redirect Location header pointed outside the mission's configured
    scope — the same ``ScopeGuard`` check the original target already had
    to pass, applied to this hop too. Raised instead of silently following
    the redirect."""


def _check_scheme(url: str) -> None:
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in _ALLOWED_SCHEMES:
        raise UnsupportedSchemeError(f"Refusing to open non-HTTP(S) URL scheme: {scheme or '(none)'!r}")


class _ScopeCheckedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect target against ``ScopeGuard`` (and the
    scheme allowlist) before following it, and caps the redirect chain
    length. Imports ``ScopeGuard`` lazily inside the method, not at module
    scope: ``nexus.foundation.guardrails.scope_guard`` imports
    ``nexus.foundation.config``, and importing that at module load time here
    would risk a circular import given how widely ``nexus.foundation.net``
    itself is imported across the codebase."""

    max_redirections = _MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from nexus.foundation.guardrails.scope_guard import ScopeGuard, ScopeGuardError

        _check_scheme(newurl)
        try:
            ScopeGuard.validate(newurl)
        except ScopeGuardError as exc:
            raise SSRFBlockedError(
                f"Refusing to follow redirect to out-of-scope target: {newurl!r} ({exc})"
            ) from exc
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_urlopen(
    url_or_request: str | urllib.request.Request,
    *,
    timeout: float = 10,
    context: ssl.SSLContext | None = None,
    **kwargs: Any,
):
    url = url_or_request.full_url if isinstance(url_or_request, urllib.request.Request) else url_or_request
    _check_scheme(url)

    handlers: list[urllib.request.BaseHandler] = [_ScopeCheckedRedirectHandler()]
    if context is not None:
        # Mirrors urlopen()'s own behaviour: an HTTPSHandler is only built
        # explicitly when a context is supplied; otherwise the default
        # opener's stock HTTPSHandler (default SSL context) is used.
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    # nosec B310 - scheme validated above (both the initial URL and every
    # redirect hop, via _ScopeCheckedRedirectHandler)
    return opener.open(url_or_request, timeout=timeout, **kwargs)
