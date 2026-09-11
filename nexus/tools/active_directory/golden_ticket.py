#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory.golden_ticket
Domain: active_directory
Real Golden Ticket risk assessment: attempts a real LDAP query of the
krbtgt account's pwdLastSet attribute and computes its real age.

Previously this hardcoded `krbtgt_age_days = 1825` behind a
"# Simulate querying" comment and always returned the same "password too
old" finding regardless of target — never touched the network. Caught
during this session's audit (an earlier audit pass wrongly cleared this
file as already-real; a later fix pass caught the mistake). Now: mirrors
kerberoast.py's honest LDAP pattern — a real bind is attempted, and
`pwdLastSet` on krbtgt is normally unreadable via anonymous bind (AD's own
ACLs protect it), so the expected, honest outcome for an anonymous probe
is STATUS_REQUIRES_CREDENTIALS, not a fabricated age.
"""
from __future__ import annotations

import datetime
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_LDAP_TIMEOUT = 5
_TOOL_NAME = "active_directory.golden_ticket"
_RECOMMENDED_MAX_AGE_DAYS = 180


def _filetime_to_datetime(filetime: int) -> datetime.datetime:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to UTC."""
    return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=filetime / 10)


def run(target: str, **kwargs: Any) -> dict:
    """Perform Golden Ticket risk analysis via a real LDAP query of krbtgt's pwdLastSet."""
    try:
        import ldap3
    except ImportError:
        return tool_result(
            _TOOL_NAME, target,
            status=STATUS_UNAVAILABLE,
            summary="ldap3 is not installed — no krbtgt query was attempted",
            error="ldap3 module not installed. Install it (pip install ldap3) for LDAP-based AD enumeration.",
        )

    username = kwargs.get("username")
    password = kwargs.get("password")

    try:
        server = ldap3.Server(target, get_info=ldap3.NONE, connect_timeout=_LDAP_TIMEOUT)
        if username:
            connection = ldap3.Connection(
                server, user=username, password=password, auto_bind=False, receive_timeout=_LDAP_TIMEOUT
            )
        else:
            connection = ldap3.Connection(server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        if not connection.bind():
            return tool_result(
                _TOOL_NAME, target,
                status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"LDAP bind to {target} was rejected — krbtgt pwdLastSet requires valid AD credentials",
                error=f"bind failed: {connection.result}",
            )
    except Exception as e:  # noqa: BLE001 - connection/network failures cover many exception types (socket, LDAP, TLS)
        return tool_result(
            _TOOL_NAME, target,
            status=STATUS_UNAVAILABLE,
            summary=f"Could not reach an LDAP service on {target}",
            error=f"LDAP connection failed: {e}",
        )

    try:
        base_dn = getattr(connection.server.info, "naming_contexts", None) if connection.server.info else None
        if not base_dn:
            connection.unbind()
            return tool_result(
                _TOOL_NAME, target,
                status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"LDAP bind to {target} succeeded but exposed no naming context to search from",
                error="no naming_contexts available; authenticated credentials are required to query krbtgt",
            )

        pwd_last_set_raw = None
        for context in base_dn:
            connection.search(
                search_base=str(context),
                search_filter="(sAMAccountName=krbtgt)",
                search_scope=ldap3.SUBTREE,
                attributes=["pwdLastSet"],
                size_limit=1,
            )
            if connection.entries:
                pwd_last_set_raw = connection.entries[0].pwdLastSet.raw_values
                break
        connection.unbind()
    except Exception as e:  # noqa: BLE001 - LDAP search-time failures
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"LDAP search failed: {e}")

    if not pwd_last_set_raw:
        return tool_result(
            _TOOL_NAME, target,
            status=STATUS_REQUIRES_CREDENTIALS,
            summary=f"LDAP search against {target} could not read krbtgt's pwdLastSet — "
                    "this attribute is normally restricted to authenticated principals",
        )

    try:
        pwd_last_set_dt = _filetime_to_datetime(int(pwd_last_set_raw[0]))
    except (ValueError, TypeError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"could not parse pwdLastSet: {e}")

    age_days = (datetime.datetime.now(datetime.timezone.utc) - pwd_last_set_dt).days
    findings: list[Finding] = []
    if age_days > _RECOMMENDED_MAX_AGE_DAYS:
        findings.append(Finding(
            title="krbtgt Account Password Age Exceeds Recommended Maximum",
            severity="high" if age_days > 1825 else "medium",
            confidence="certain",
            affected_asset=f"krbtgt@{target}",
            evidence=f"Real LDAP query shows the krbtgt account's pwdLastSet was {pwd_last_set_dt.isoformat()}, "
                     f"{age_days} days ago (recommended maximum: {_RECOMMENDED_MAX_AGE_DAYS} days). "
                     "A long-lived krbtgt key increases the value of any stolen key material to an attacker "
                     "forging Golden Tickets.",
            remediation="Reset the krbtgt account password twice (24+ hours apart) to invalidate all existing "
                        "Kerberos tickets and rotate the key used to sign them.",
            tool=_TOOL_NAME,
            references=["CWE-287", "MITRE ATT&CK T1558.001"],
        ))
    else:
        findings.append(Finding(
            title="krbtgt Account Password Age is Within Acceptable Limits",
            severity="info",
            confidence="certain",
            affected_asset=f"krbtgt@{target}",
            evidence=f"Real LDAP query shows the krbtgt account's pwdLastSet was {pwd_last_set_dt.isoformat()}, "
                     f"{age_days} days ago.",
            remediation="Continue regular krbtgt password rotation every 180 days.",
            tool=_TOOL_NAME,
            references=["CWE-287"],
        ))

    return tool_result(
        _TOOL_NAME, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Golden Ticket risk analysis completed via real LDAP query. krbtgt age: {age_days} days.",
        metadata={"krbtgt_age_days": age_days, "krbtgt_pwd_last_set": pwd_last_set_dt.isoformat()},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "active_directory",
    "status": "completed",
    "description": "Real LDAP query of krbtgt's pwdLastSet to assess Golden Ticket risk (requires authenticated bind)",
    "parameters": {
        "target": "Target domain controller hostname or IP",
        "username": "(optional) AD username for authenticated bind — required to read pwdLastSet",
        "password": "(optional) AD password for authenticated bind",
    },
})