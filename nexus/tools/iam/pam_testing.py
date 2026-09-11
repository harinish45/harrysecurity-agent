#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam.pam_testing
Domain: iam
Privileged Access Management posture is not a network-probeable property —
an unauthenticated scan of a target host cannot see vault-managed account
metadata. When real privileged-account data is supplied (e.g. exported from
the PAM vault: CyberArk, HashiCorp Vault, BeyondTrust), this does a real
analysis of it (shared accounts without checkout, stale rotation, no
session recording). Absent that data, it honestly degrades to
STATUS_REQUIRES_CREDENTIALS instead of fabricating findings from a bare
target string.

Previously this was a bare DNS resolve + a handful of unauthenticated HTTP
GETs against generic paths like /login, /admin (byte-for-byte identical to
19 other stub tools, and none of it actually PAM-specific) — caught during
this session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_REQUIRES_CREDENTIALS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_STALE_ROTATION_DAYS = 90


def run(target: str, pam_account_data: list[dict] | None = None, **kwargs: Any) -> dict:
    """Real analysis of supplied privileged-account data; honest degrade without it.

    Parameters
    ----------
    target : str
        The PAM vault / target system the account data relates to (labeling only).
    pam_account_data : list[dict], optional
        Account records exported from the PAM vault, e.g.
        ``[{"account": "svc_backup", "shared": True, "checkout_required": False,
        "session_recording": False, "last_rotated_days": 120}, ...]``.
    """
    tool_name = "iam.pam_testing"
    data = pam_account_data if pam_account_data is not None else kwargs.get("pam_account_data")

    if not data:
        return tool_result(
            tool_name, target,
            status=STATUS_REQUIRES_CREDENTIALS,
            summary=f"PAM posture review for {target} requires exported privileged-account data from the "
                    f"PAM vault (e.g. CyberArk, HashiCorp Vault, BeyondTrust) — pass it as "
                    f"pam_account_data=[{{'account': ..., 'shared': bool, 'checkout_required': bool, "
                    f"'session_recording': bool, 'last_rotated_days': int}}, ...]. Unauthenticated network "
                    f"probing of {target} cannot see vault-managed account metadata.",
            error="requires_credentials: no PAM account data supplied",
        )

    findings: list[Finding] = []
    shared_unchecked = 0
    unrecorded = 0
    stale_rotation = 0
    for entry in data:
        account = str(entry.get("account", "unknown"))
        if entry.get("shared") and not entry.get("checkout_required"):
            shared_unchecked += 1
            findings.append(Finding(
                title=f"Shared privileged account without checkout enforcement: {account}",
                severity="high", confidence="certain",
                affected_asset=str(target),
                evidence=f"account={account}, shared=True, checkout_required=False",
                remediation="Require one-time credential checkout for all shared privileged accounts.",
                tool=tool_name,
                references=["CWE-732"],
            ))
        if not entry.get("session_recording"):
            unrecorded += 1
            findings.append(Finding(
                title=f"No session recording for privileged account: {account}",
                severity="medium", confidence="certain",
                affected_asset=str(target),
                evidence=f"account={account}, session_recording=False",
                remediation="Enable session recording for all privileged-account sessions.",
                tool=tool_name,
                references=["CWE-778"],
            ))
        last_rotated = entry.get("last_rotated_days")
        if isinstance(last_rotated, (int, float)) and last_rotated > _STALE_ROTATION_DAYS:
            stale_rotation += 1
            findings.append(Finding(
                title=f"Privileged account credential rotation overdue: {account}",
                severity="medium", confidence="certain",
                affected_asset=str(target),
                evidence=f"account={account}, last_rotated_days={last_rotated} (> {_STALE_ROTATION_DAYS})",
                remediation="Rotate privileged-account credentials at least every "
                             f"{_STALE_ROTATION_DAYS} days (shorter for high-risk accounts).",
                tool=tool_name,
                references=["CWE-262"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Real analysis of {len(data)} supplied privileged-account record(s) for {target}: "
                f"{shared_unchecked} shared-without-checkout, {unrecorded} unrecorded, "
                f"{stale_rotation} rotation-overdue.",
        metadata={
            "total_accounts": len(data),
            "shared_unchecked_count": shared_unchecked,
            "unrecorded_count": unrecorded,
            "stale_rotation_count": stale_rotation,
        },
    )


tool_registry.register("iam.pam_testing", run, metadata={
    "name": "iam.pam_testing",
    "domain": "iam",
    "status": "completed",
    "description": "Real analysis of supplied PAM vault account data (shared/unchecked accounts, missing "
                    "session recording, stale rotation); requires vault-exported data since this isn't "
                    "network-probeable",
    "parameters": {
        "target": "The PAM vault / target system the account data relates to",
        "pam_account_data": "List of account records exported from the PAM vault",
    },
})
