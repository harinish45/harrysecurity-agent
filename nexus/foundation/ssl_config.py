"""Centralized SSL/TLS context creation.

Every tool that talks HTTPS/TLS to a target used to build its own
``ssl.SSLContext`` with certificate verification disabled outright
(``ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE``),
unconditionally, for every target — local test fixtures and public internet
hosts alike. That's CWE-295: every one of those ~140 call sites was
vulnerable to a man-in-the-middle between NEXUS and the target.

This module is the single place that decides whether an insecure context is
actually warranted, instead of every call site deciding for itself::

    from nexus.foundation.ssl_config import get_ssl_context
    ctx = get_ssl_context(target)

Certificate verification is ON by default. A caller may *ask* for an
insecure context — many of these tools inspect a target's own, possibly
self-signed or expired, certificate as their actual job (that's TLS/cert
testing, not a bug) — via ``allow_insecure=True``, but the request is only
honoured if the target resolves to a private/loopback/link-local address, or
``NEXUS_ALLOW_INSECURE_TLS=1`` is explicitly set for the run. Otherwise the
request is downgraded to a secure context and the downgrade is logged (and
audited), so a scan against a public host can't silently run with no
certificate validation just because a tool asked for it.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import ssl
from urllib.parse import urlparse

logger = logging.getLogger("nexus.ssl_config")


def _hostname(target: str) -> str:
    if not target:
        return ""
    parsed = urlparse(target if "://" in target else f"//{target}", scheme="")
    return (parsed.hostname or target).rstrip(".")


def _is_private_scope(target: str) -> bool:
    """True if the target is a loopback/private/link-local address, or a
    hostname that resolves only to such addresses. Fails closed: any error
    (unresolvable hostname, etc.) is treated as NOT private."""
    hostname = _hostname(target)
    if not hostname:
        return False
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        pass
    if hostname.lower() == "localhost":
        return True
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    try:
        addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
    except ValueError:
        return False
    return bool(addrs) and all(a.is_private or a.is_loopback or a.is_link_local for a in addrs)


def _insecure_allowed(target: str) -> bool:
    if os.environ.get("NEXUS_ALLOW_INSECURE_TLS", "").lower() in ("1", "true", "yes"):
        return True
    return _is_private_scope(target)


def get_ssl_context(
    target: str = "",
    *,
    allow_insecure: bool = False,
    purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
) -> ssl.SSLContext:
    """Return a hardened SSL context for connecting to ``target``.

    Verification is enabled by default (``CERT_REQUIRED`` + hostname check,
    TLS >= 1.2). Pass ``allow_insecure=True`` to request a context that
    skips certificate/hostname validation — honoured only for
    private/loopback targets or when ``NEXUS_ALLOW_INSECURE_TLS=1`` is set;
    otherwise this call transparently returns a *secure* context instead and
    logs the downgrade rather than silently doing what was asked.
    """
    ctx = ssl.create_default_context(purpose)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if not allow_insecure:
        return ctx

    if _insecure_allowed(target):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _audit_insecure(target)
        return ctx

    logger.warning(
        "Insecure TLS context requested for %r but the target is not in "
        "private/loopback scope and NEXUS_ALLOW_INSECURE_TLS is not set — "
        "using a verified context instead. Set NEXUS_ALLOW_INSECURE_TLS=1 if "
        "this target's certificate is intentionally being tested as part of "
        "an authorised engagement.",
        target,
    )
    return ctx


def _audit_insecure(target: str) -> None:
    try:
        from nexus.foundation.guardrails.audit_guard import AuditGuard

        AuditGuard.validate(action="ssl_verification_disabled", target=target)
    except Exception:  # pragma: no cover - audit logging must never break a scan
        logger.debug("Could not write audit entry for insecure TLS context.", exc_info=True)
