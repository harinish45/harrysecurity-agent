#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam.ldap_testing
Domain: iam
Real, read-only LDAP connectivity/hardening checks (mirrors the real-bind
style of nexus/tools/active_directory/kerberoast.py): a genuine anonymous
bind attempt against target:389, and a genuine StartTLS negotiation
attempt on that same port.

Previously this was a bare DNS resolve + a handful of unauthenticated HTTP
GETs against generic paths like /login, /admin (byte-for-byte identical to
19 other stub tools, and none of it actually LDAP) — caught during this
session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_LDAP_TIMEOUT = 5
_LDAP_PORT = 389


def run(target: str, **kwargs: Any) -> dict:
    """Real anonymous-bind and StartTLS checks against an LDAP service."""
    tool_name = "iam.ldap_testing"

    try:
        import ldap3
    except ImportError:
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary="ldap3 is not installed — no LDAP checks were attempted",
            error="ldap3 module not installed. Install it (pip install ldap3) for real LDAP testing.",
        )

    try:
        server = ldap3.Server(target, port=_LDAP_PORT, get_info=ldap3.NONE, connect_timeout=_LDAP_TIMEOUT)
        connection = ldap3.Connection(server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        anonymous_bind_allowed = connection.bind()
    except Exception as e:  # noqa: BLE001 - connection/network failures cover many exception types
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary=f"Could not reach an LDAP service on {target}:{_LDAP_PORT}",
            error=f"LDAP connection failed: {e}",
        )

    findings: list[Finding] = []
    if anonymous_bind_allowed:
        findings.append(Finding(
            title="Anonymous LDAP bind allowed",
            severity="high", confidence="certain",
            affected_asset=f"{target}:{_LDAP_PORT}",
            evidence="A real LDAP bind() with no credentials against this server returned success.",
            remediation="Disable anonymous LDAP binds; require authentication for all LDAP operations.",
            tool=tool_name,
            references=["CWE-287", "CWE-306"],
        ))

    # StartTLS must be negotiated before any bind on the connection it's
    # attempted on, so this is a fresh connection rather than reuse of the
    # one above.
    starttls_supported = False
    try:
        tls_server = ldap3.Server(target, port=_LDAP_PORT, get_info=ldap3.NONE, connect_timeout=_LDAP_TIMEOUT)
        tls_connection = ldap3.Connection(tls_server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        tls_connection.open()
        starttls_supported = bool(tls_connection.start_tls())
        tls_connection.unbind()
    except Exception:
        starttls_supported = False

    if not starttls_supported:
        findings.append(Finding(
            title="StartTLS not available on LDAP (port 389)",
            severity="medium", confidence="high",
            affected_asset=f"{target}:{_LDAP_PORT}",
            evidence="A real StartTLS negotiation attempt on this connection did not succeed.",
            remediation="Enable and require StartTLS (or LDAPS on 636) so LDAP traffic isn't sent in cleartext.",
            tool=tool_name,
            references=["CWE-319"],
        ))

    try:
        connection.unbind()
    except Exception:
        pass

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Real LDAP connectivity checks against {target}:{_LDAP_PORT} completed: "
                f"anonymous_bind_allowed={anonymous_bind_allowed}, starttls_supported={starttls_supported}.",
        metadata={"anonymous_bind_allowed": anonymous_bind_allowed, "starttls_supported": starttls_supported},
    )


tool_registry.register("iam.ldap_testing", run, metadata={
    "name": "iam.ldap_testing",
    "domain": "iam",
    "status": "completed",
    "description": "Real LDAP anonymous-bind and StartTLS-support checks via a genuine ldap3 connection",
    "parameters": {
        "target": "LDAP server hostname or IP",
    },
})
