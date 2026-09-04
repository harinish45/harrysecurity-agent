"""Scheme-validated HTTP(S) fetch.

``urllib.request.urlopen()`` will happily follow ``file://``, ``ftp://``, and
other non-HTTP schemes — if a URL built from attacker-influenced input (a
scan target, a redirect Location header) ever reaches it unchecked, that's an
arbitrary local file read or protocol-smuggling primitive (bandit B310).
``safe_urlopen()`` is the one place in the codebase that calls
``urllib.request.urlopen()`` directly; every tool that used to call it
directly now calls this instead, so the scheme check lives in exactly one
place rather than being repeated (or forgotten) per call site.
"""
from __future__ import annotations

import ssl
import urllib.request
from typing import Any

_ALLOWED_SCHEMES = {"http", "https"}


class UnsupportedSchemeError(ValueError):
    pass


def safe_urlopen(
    url_or_request: str | urllib.request.Request,
    *,
    timeout: float = 10,
    context: ssl.SSLContext | None = None,
    **kwargs: Any,
):
    url = url_or_request.full_url if isinstance(url_or_request, urllib.request.Request) else url_or_request
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in _ALLOWED_SCHEMES:
        raise UnsupportedSchemeError(f"Refusing to open non-HTTP(S) URL scheme: {scheme or '(none)'!r}")
    return urllib.request.urlopen(url_or_request, timeout=timeout, context=context, **kwargs)  # nosec B310 - scheme validated above
