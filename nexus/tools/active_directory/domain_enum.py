#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory.domain_enum
Domain: active_directory
Real, read-only AD domain enumeration: anonymous-bind LDAP root-DSE lookup
plus a real object-count enumeration (users/groups/computers) when the
directory exposes a searchable naming context.

Previously a generic "DNS resolve + bare HTTP GET" stub identical to dozens
of other tool files across the codebase — never touched LDAP at all despite
the name. Caught during this session's audit. Now: a real anonymous LDAP
bind (matching kerberoast.py's established honest-degrade convention) is
attempted; only genuine LDAP responses produce findings.
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
    """Perform read-only AD domain enumeration via anonymous-bind LDAP root-DSE + object counts."""
    tool_name = "active_directory.domain_enum"

    try:
        import ldap3
    except ImportError:
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary="ldap3 is not installed — no domain enumeration was attempted",
            error="ldap3 module not installed. Install it (pip install ldap3) for LDAP-based AD enumeration.",
        )

    try:
        server = ldap3.Server(target, get_info=ldap3.ALL, connect_timeout=_LDAP_TIMEOUT)
        connection = ldap3.Connection(server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        if not connection.bind():
            return tool_result(
                tool_name, target,
                status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"Anonymous LDAP bind to {target} was rejected — domain enumeration requires valid AD credentials",
                error=f"bind failed: {connection.result}",
            )
    except Exception as e:  # noqa: BLE001 - connection/network failures cover many exception types
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary=f"Could not reach an LDAP service on {target}",
            error=f"LDAP connection failed: {e}",
        )

    findings: list[Finding] = []
    info = connection.server.info
    naming_contexts = list(getattr(info, "naming_contexts", None) or []) if info else []
    default_naming_context = None
    if info is not None:
        try:
            other = info.other or {}
            ctx = other.get("defaultNamingContext")
            default_naming_context = ctx[0] if ctx else None
        except Exception:  # noqa: BLE001 - root-DSE attribute layout varies by server
            default_naming_context = None
    base_dn = default_naming_context or (naming_contexts[0] if naming_contexts else None)

    if info is not None:
        findings.append(Finding(
            title="AD Domain Controller Identified (root-DSE)",
            severity="info",
            confidence="certain",
            affected_asset=target,
            evidence=f"Root-DSE exposed via anonymous bind: naming_contexts={naming_contexts}, "
                     f"vendor={getattr(info, 'vendor_name', 'unknown')}, "
                     f"server_type={getattr(info, 'server_type', 'unknown')}",
            remediation="Root-DSE disclosure to anonymous binds is standard LDAP behavior, but confirm "
                        "anonymous bind is not permitted for deeper directory queries.",
            tool=tool_name,
            references=["MITRE ATT&CK T1087.002"],
        ))

    object_counts: dict[str, int] = {}
    if base_dn:
        counts_spec = {
            "users": "(objectClass=user)",
            "groups": "(objectClass=group)",
            "computers": "(objectClass=computer)",
        }
        for label, ldap_filter in counts_spec.items():
            try:
                connection.search(
                    search_base=base_dn,
                    search_filter=ldap_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=["cn"],
                    size_limit=1000,
                )
                object_counts[label] = len(connection.entries)
            except Exception:  # noqa: BLE001 - a single object-class query failing shouldn't abort the rest
                object_counts[label] = -1

        real_counts = {k: v for k, v in object_counts.items() if v >= 0}
        if real_counts:
            findings.append(Finding(
                title="Domain Object Enumeration via Anonymous LDAP Bind",
                severity="medium" if any(v > 0 for v in real_counts.values()) else "info",
                confidence="certain",
                affected_asset=target,
                evidence=f"Anonymous bind against base DN '{base_dn}' returned real object counts: {real_counts}. "
                         f"If non-zero, this directory permits anonymous enumeration of domain objects.",
                remediation="Disable anonymous LDAP bind (dsHeuristics) unless explicitly required; "
                            "restrict anonymous queries via LDAP query policies.",
                tool=tool_name,
                references=["CWE-287", "MITRE ATT&CK T1087.002"],
            ))
    connection.unbind()

    if not findings:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"Anonymous LDAP bind to {target} succeeded but exposed no root-DSE info or naming context",
        )
    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Domain enumeration completed via real LDAP queries against {target}",
        metadata={"base_dn": base_dn, "object_counts": object_counts},
    )


tool_registry.register("active_directory.domain_enum", run, metadata={
    "name": "active_directory.domain_enum",
    "domain": "active_directory",
    "status": "completed",
    "description": "Real, read-only AD domain enumeration via anonymous-bind LDAP root-DSE + object-count queries",
    "parameters": {"target": "Target domain controller hostname or IP"},
})
