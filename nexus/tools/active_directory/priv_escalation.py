#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory.priv_escalation
Domain: active_directory
Real, read-only AD privilege-escalation-path indicators: anonymous-bind
LDAP search for accounts with adminCount=1 (protected/privileged accounts)
and userAccountControl flags indicating unconstrained delegation
(TRUSTED_FOR_DELEGATION, 0x80000).

Previously a generic "DNS resolve + bare HTTP GET" stub. Caught during this
session's audit. Now: real LDAP attribute queries; only real query results
produce findings.
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
_UAC_TRUSTED_FOR_DELEGATION = 0x80000  # unconstrained delegation flag


def run(target: str, **kwargs: Any) -> dict:
    """Perform read-only AD privilege-escalation indicator checks via anonymous-bind LDAP."""
    tool_name = "active_directory.priv_escalation"

    try:
        import ldap3
    except ImportError:
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary="ldap3 is not installed — no privilege-escalation checks were attempted",
            error="ldap3 module not installed. Install it (pip install ldap3) for LDAP-based AD enumeration.",
        )

    try:
        server = ldap3.Server(target, get_info=ldap3.ALL, connect_timeout=_LDAP_TIMEOUT)
        connection = ldap3.Connection(server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        if not connection.bind():
            return tool_result(
                tool_name, target,
                status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"Anonymous LDAP bind to {target} was rejected — privilege-escalation checks require valid AD credentials",
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
        except Exception:  # noqa: BLE001
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

    findings: list[Finding] = []
    admincount_accounts: list[str] = []
    delegation_accounts: list[str] = []

    try:
        connection.search(
            search_base=base_dn,
            search_filter="(&(objectClass=user)(adminCount=1))",
            search_scope=ldap3.SUBTREE,
            attributes=["sAMAccountName"],
            size_limit=200,
        )
        admincount_accounts = [str(getattr(e, "sAMAccountName", "unknown")) for e in connection.entries]
    except Exception:  # noqa: BLE001 - a single query failing shouldn't abort the rest
        admincount_accounts = []

    try:
        connection.search(
            search_base=base_dn,
            search_filter=f"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={_UAC_TRUSTED_FOR_DELEGATION}))",
            search_scope=ldap3.SUBTREE,
            attributes=["sAMAccountName"],
            size_limit=200,
        )
        delegation_accounts = [str(getattr(e, "sAMAccountName", "unknown")) for e in connection.entries]
    except Exception:  # noqa: BLE001
        delegation_accounts = []
    connection.unbind()

    if admincount_accounts:
        findings.append(Finding(
            title="Accounts with adminCount=1 Enumerable via Anonymous LDAP Bind",
            severity="medium",
            confidence="certain",
            affected_asset=target,
            evidence=f"Real LDAP search returned {len(admincount_accounts)} account(s) with adminCount=1 "
                     f"(protected/privileged accounts): {admincount_accounts[:10]}",
            remediation="These are legitimately privileged accounts (AdminSDHolder-protected) — confirm "
                        "membership is expected and audit for stale/orphaned adminCount=1 flags.",
            tool=tool_name,
            references=["MITRE ATT&CK T1078.002"],
        ))

    if delegation_accounts:
        findings.append(Finding(
            title="Accounts Configured for Unconstrained Kerberos Delegation",
            severity="high",
            confidence="certain",
            affected_asset=target,
            evidence=f"Real LDAP search found {len(delegation_accounts)} account(s) with "
                     f"userAccountControl TRUSTED_FOR_DELEGATION set: {delegation_accounts[:10]}. "
                     f"Compromising one of these hosts/accounts can expose cached TGTs of any user "
                     f"that authenticates to it.",
            remediation="Replace unconstrained delegation with constrained delegation or resource-based "
                        "constrained delegation (RBCD); mark sensitive accounts as 'Account is sensitive "
                        "and cannot be delegated'.",
            tool=tool_name,
            references=["CWE-287", "MITRE ATT&CK T1134.005"],
        ))

    if not findings:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"LDAP privilege-escalation indicator queries against {target} completed; nothing visible via anonymous bind",
        )
    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Privilege-escalation indicator checks completed via real LDAP queries against {target}",
        metadata={"admincount_accounts": admincount_accounts, "unconstrained_delegation_accounts": delegation_accounts},
    )


tool_registry.register("active_directory.priv_escalation", run, metadata={
    "name": "active_directory.priv_escalation",
    "domain": "active_directory",
    "status": "completed",
    "description": "Real, read-only AD privilege-escalation indicator checks (adminCount=1, unconstrained delegation) via anonymous-bind LDAP",
    "parameters": {"target": "Target domain controller hostname or IP"},
})
