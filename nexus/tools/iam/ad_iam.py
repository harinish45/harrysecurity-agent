#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam.ad_iam
Domain: iam
Real Active Directory IAM composite: a genuine anonymous-bind LDAP root DSE
read (domain/forest functional level, naming context — real exposure check,
mirrors the real-bind style of nexus/tools/active_directory/kerberoast.py)
plus a real composite call into the already-real
active_directory.kerberoast tool via tool_registry for an SPN-enumeration
angle on the same target.

Previously this was a bare DNS resolve + a handful of unauthenticated HTTP
GETs against generic paths like /login, /admin (byte-for-byte identical to
19 other stub tools, and none of it actually AD/IAM-specific) — caught
during this session's audit.
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
_ROOT_DSE_ATTRS = (
    "defaultNamingContext", "domainFunctionality", "forestFunctionality",
    "supportedLDAPVersion", "dnsHostName",
)


def _read_root_dse(target: str, ldap3: Any) -> tuple[bool | None, dict, str | None]:
    """Real anonymous-bind root DSE read. Returns (bind_ok_or_None, info, error)."""
    try:
        server = ldap3.Server(target, get_info=ldap3.ALL, connect_timeout=_LDAP_TIMEOUT)
        connection = ldap3.Connection(server, auto_bind=False, receive_timeout=_LDAP_TIMEOUT)
        bind_ok = connection.bind()
    except Exception as e:  # noqa: BLE001 - connection/network failures cover many exception types
        return None, {}, str(e)

    if not bind_ok:
        return False, {}, None

    info: dict[str, Any] = {}
    server_info = connection.server.info
    if server_info is not None:
        other = getattr(server_info, "other", None) or {}
        for attr in _ROOT_DSE_ATTRS:
            val = getattr(server_info, attr, None) or other.get(attr)
            if val:
                info[attr] = val if isinstance(val, (str, int)) else str(val)
    try:
        connection.unbind()
    except Exception:
        pass
    return True, info, None


def run(target: str, **kwargs: Any) -> dict:
    """Real AD root-DSE exposure check plus a composite kerberoast SPN check."""
    tool_name = "iam.ad_iam"

    try:
        import ldap3
    except ImportError:
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary="ldap3 is not installed — no AD/IAM checks were attempted",
            error="ldap3 module not installed. Install it (pip install ldap3) for real AD/IAM testing.",
        )

    bind_ok, root_dse, ldap_error = _read_root_dse(target, ldap3)

    findings: list[Finding] = []
    if bind_ok and root_dse:
        findings.append(Finding(
            title="Active Directory root DSE readable via anonymous LDAP bind",
            severity="medium", confidence="certain",
            affected_asset=str(target),
            evidence=f"A real anonymous LDAP bind succeeded and exposed root DSE attributes: {root_dse}",
            remediation="Restrict anonymous LDAP access; require authentication before exposing "
                         "domain/forest information.",
            tool=tool_name,
            references=["CWE-287", "MITRE ATT&CK T1069"],
        ))
        ldap_note = "anonymous bind succeeded"
    elif bind_ok is False:
        ldap_note = "anonymous bind rejected (expected/hardened)"
    else:
        ldap_note = f"LDAP connection failed: {ldap_error}"

    # Real composite: reuse the already-real active_directory.kerberoast
    # tool for an SPN-enumeration angle on the same target.
    kerberoast_result: dict = {}
    try:
        kerberoast_fn = tool_registry.get("active_directory.kerberoast")
        kerberoast_result = kerberoast_fn(target=target)
    except Exception as e:  # noqa: BLE001 - composite sub-tool failures shouldn't abort this tool
        kerberoast_result = {"status": "failed", "error": str(e)[:200], "findings": []}

    for f in kerberoast_result.get("findings") or []:
        if isinstance(f, dict):
            findings.append(Finding(**{**f, "tool": tool_name}))

    if bind_ok is None and not findings:
        return tool_result(
            tool_name, target,
            status=STATUS_UNAVAILABLE,
            summary=f"Could not reach an LDAP/AD service on {target} for IAM checks ({ldap_note}); "
                    f"composite kerberoast status={kerberoast_result.get('status', 'n/a')}.",
            error=ldap_error,
        )

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Real AD/IAM checks against {target}: {ldap_note}; composite kerberoast SPN check "
                f"status={kerberoast_result.get('status', 'n/a')}.",
        metadata={"root_dse": root_dse, "kerberoast_status": kerberoast_result.get("status")},
    )


tool_registry.register("iam.ad_iam", run, metadata={
    "name": "iam.ad_iam",
    "domain": "iam",
    "status": "completed",
    "description": "Real AD root-DSE anonymous-bind exposure check plus a composite "
                    "active_directory.kerberoast SPN-enumeration call",
    "parameters": {
        "target": "Active Directory domain controller hostname or IP",
    },
})
