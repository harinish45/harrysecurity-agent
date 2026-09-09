#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory.kerberoast
Domain: active_directory
Real, read-only Kerberoasting reconnaissance: anonymous-bind LDAP SPN
enumeration against the target's LDAP service.

Previously this unconditionally fabricated SPN findings
(`f"MSSQLSvc/{target}:1433"` etc., string-templated from the target name
with no LDAP query ever made) regardless of whether `target` was even an
Active Directory server. Caught during this session's audit. Now: a real
bind is attempted; only a genuine LDAP search response produces an
"SPN Identified" finding, and every other path (no `ldap3`, connection
refused, anonymous bind rejected) reports an honest non-completed status
instead of guessing.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_LDAP_TIMEOUT = 5


def run(target: str, **kwargs: Any) -> dict:
    """Perform Kerberoasting reconnaissance (read-only, anonymous-bind SPN enumeration)."""
    tool_name = "active_directory.kerberoast"

    try:
        import ldap3
    except ImportError:
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary="ldap3 is not installed — no SPN enumeration was attempted",
            error="ldap3 module not installed. Install it (pip install ldap3) for LDAP-based AD enumeration.",
        )

    try:
        server = ldap3.Server(target, get_info=ldap3.NONE, connect_timeout=_LDAP_TIMEOUT)
        connection = ldap3.Connection(server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        if not connection.bind():
            return tool_result(
                tool_name, target,
                status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"Anonymous LDAP bind to {target} was rejected — SPN enumeration requires valid AD credentials",
                error=f"bind failed: {connection.result}",
            )
    except Exception as e:  # noqa: BLE001 - connection/network failures cover many exception types (socket, LDAP, TLS)
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary=f"Could not reach an LDAP service on {target}",
            error=f"LDAP connection failed: {e}",
        )

    try:
        # No base DN is known without credentials/prior directory info — a
        # bind DN's own domain components are the only base we can derive
        # honestly from an anonymous bind. If the server exposes no bind DN
        # or naming context, we genuinely cannot search further; that's a
        # real, reportable limitation, not a reason to fabricate a base.
        base_dn = getattr(connection.server.info, "naming_contexts", None) if connection.server.info else None
        if not base_dn:
            connection.unbind()
            return tool_result(
                tool_name, target,
                status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"Anonymous bind to {target} succeeded but exposed no naming context to search from",
                error="no naming_contexts available from anonymous bind; authenticated credentials are required",
            )

        findings: list[Finding] = []
        spns_found: list[str] = []
        for context in base_dn:
            connection.search(
                search_base=str(context),
                search_filter="(servicePrincipalName=*)",
                search_scope=ldap3.SUBTREE,
                attributes=["servicePrincipalName", "sAMAccountName"],
                size_limit=50,
            )
            for entry in connection.entries:
                account = str(getattr(entry, "sAMAccountName", "") or "")
                for spn in getattr(entry, "servicePrincipalName", []) or []:
                    spn_str = str(spn)
                    spns_found.append(spn_str)
                    findings.append(Finding(
                        title="Service Principal Name (SPN) Identified",
                        severity="medium",
                        confidence="certain",
                        affected_asset=target,
                        evidence=f"SPN '{spn_str}' returned by real LDAP search against {context} "
                                 f"(account: {account or 'unknown'}). Accounts with SPNs are potentially kerberoastable.",
                        remediation="Ensure service accounts have strong, complex passwords (25+ characters) "
                                    "and use Managed Service Accounts (gMSA).",
                        tool=tool_name,
                        references=["CWE-287", "MITRE ATT&CK T1558.003"],
                    ))
        connection.unbind()
    except Exception as e:  # noqa: BLE001 - LDAP search-time failures
        return tool_result(tool_name, target, status=STATUS_FAILED, error=f"LDAP search failed: {e}")

    if not spns_found:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"LDAP search against {target} completed; no SPNs returned",
        )
    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Kerberoast reconnaissance completed via real LDAP search. Found {len(spns_found)} SPN(s).",
        metadata={"spns_found": spns_found},
    )


tool_registry.register("active_directory.kerberoast", run, metadata={
    "name": "active_directory.kerberoast",
    "domain": "active_directory",
    "status": "completed",
    "description": "Real, read-only Kerberoasting reconnaissance via anonymous-bind LDAP SPN enumeration",
    "parameters": {"target": "Target domain controller hostname or IP"},
})
