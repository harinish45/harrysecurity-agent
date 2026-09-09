#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory.gpo_analysis
Domain: active_directory
Real, read-only Group Policy Object enumeration: anonymous-bind LDAP search
for groupPolicyContainer objects under the domain's System\\Policies
container.

Previously a generic "DNS resolve + bare HTTP GET" stub. Caught during this
session's audit. Now: a real LDAP query for real GPO objects; only a real
result set produces findings.
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
    """Perform read-only GPO enumeration via anonymous-bind LDAP search."""
    tool_name = "active_directory.gpo_analysis"

    try:
        import ldap3
    except ImportError:
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary="ldap3 is not installed — no GPO enumeration was attempted",
            error="ldap3 module not installed. Install it (pip install ldap3) for LDAP-based AD enumeration.",
        )

    try:
        server = ldap3.Server(target, get_info=ldap3.ALL, connect_timeout=_LDAP_TIMEOUT)
        connection = ldap3.Connection(server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        if not connection.bind():
            return tool_result(
                tool_name, target,
                status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"Anonymous LDAP bind to {target} was rejected — GPO enumeration requires valid AD credentials",
                error=f"bind failed: {connection.result}",
            )
    except Exception as e:  # noqa: BLE001 - connection/network failures cover many exception types
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary=f"Could not reach an LDAP service on {target}",
            error=f"LDAP connection failed: {e}",
        )

    info = connection.server.info
    base_dn = None
    if info is not None:
        try:
            other = info.other or {}
            ctx = other.get("defaultNamingContext")
            base_dn = ctx[0] if ctx else None
        except Exception:  # noqa: BLE001 - root-DSE attribute layout varies by server
            base_dn = None
        if not base_dn:
            naming_contexts = list(getattr(info, "naming_contexts", None) or [])
            base_dn = naming_contexts[0] if naming_contexts else None

    if not base_dn:
        connection.unbind()
        return tool_result(
            tool_name, target,
            status=STATUS_REQUIRES_CREDENTIALS,
            summary=f"Anonymous bind to {target} succeeded but exposed no naming context to search from",
            error="no defaultNamingContext available from anonymous bind; authenticated credentials are required",
        )

    policies_dn = f"CN=Policies,CN=System,{base_dn}"
    findings: list[Finding] = []
    gpos_found: list[dict] = []
    try:
        connection.search(
            search_base=policies_dn,
            search_filter="(objectClass=groupPolicyContainer)",
            search_scope=ldap3.SUBTREE,
            attributes=["displayName", "cn", "gPCFileSysPath", "versionNumber"],
            size_limit=200,
        )
        for entry in connection.entries:
            gpo = {
                "name": str(getattr(entry, "displayName", "") or getattr(entry, "cn", "unnamed")),
                "guid": str(getattr(entry, "cn", "")),
                "path": str(getattr(entry, "gPCFileSysPath", "")),
                "version": str(getattr(entry, "versionNumber", "")),
            }
            gpos_found.append(gpo)
    except Exception as e:  # noqa: BLE001 - LDAP search-time failures
        connection.unbind()
        return tool_result(tool_name, target, status=STATUS_FAILED, error=f"LDAP GPO search failed: {e}")
    connection.unbind()

    if not gpos_found:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"LDAP search against {policies_dn} completed; no GPO objects visible via anonymous bind",
        )

    findings.append(Finding(
        title="Group Policy Objects Enumerable via Anonymous LDAP Bind",
        severity="medium",
        confidence="certain",
        affected_asset=target,
        evidence=f"Anonymous bind returned {len(gpos_found)} real GPO object(s) from {policies_dn}: "
                 f"{[g['name'] for g in gpos_found][:10]}",
        remediation="Restrict anonymous LDAP access to the Policies container; review GPO SYSVOL "
                    "permissions and audit which GPOs apply privileged settings.",
        tool=tool_name,
        references=["CWE-287", "MITRE ATT&CK T1615"],
    ))
    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"GPO enumeration completed via real LDAP search. Found {len(gpos_found)} GPO object(s).",
        metadata={"gpos_found": gpos_found},
    )


tool_registry.register("active_directory.gpo_analysis", run, metadata={
    "name": "active_directory.gpo_analysis",
    "domain": "active_directory",
    "status": "completed",
    "description": "Real, read-only GPO enumeration via anonymous-bind LDAP search of the Policies container",
    "parameters": {"target": "Target domain controller hostname or IP"},
})
