#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam.mfa_reviews
Domain: iam
MFA policy/enrollment review is not a network-probeable property — an
unauthenticated scan of a target host cannot see per-user MFA enrollment.
When real enrollment/policy data is supplied (e.g. exported from the
identity provider's admin API: Okta, Azure AD, Duo), this does a real
analysis of it (no-MFA users, SMS/voice-only enrollment). Absent that data,
it honestly degrades to STATUS_REQUIRES_CREDENTIALS instead of fabricating
findings from a bare target string.

Previously this was a bare DNS resolve + a handful of unauthenticated HTTP
GETs against generic paths like /login, /admin (byte-for-byte identical to
19 other stub tools, and none of it actually MFA-specific) — caught during
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

_WEAK_METHODS = {"sms", "voice"}


def run(target: str, mfa_enrollment_data: list[dict] | None = None, **kwargs: Any) -> dict:
    """Real analysis of supplied MFA enrollment data; honest degrade without it.

    Parameters
    ----------
    target : str
        The identity provider / tenant the enrollment data relates to (labeling only).
    mfa_enrollment_data : list[dict], optional
        Enrollment records exported from the IdP's admin API, e.g.
        ``[{"user": "alice", "methods": ["totp"]}, {"user": "bob", "methods": []}]``.
    """
    tool_name = "iam.mfa_reviews"
    data = mfa_enrollment_data if mfa_enrollment_data is not None else kwargs.get("mfa_enrollment_data")

    if not data:
        return tool_result(
            tool_name, target,
            status=STATUS_REQUIRES_CREDENTIALS,
            summary=f"MFA policy review for {target} requires exported enrollment/policy data from the "
                    f"identity provider's admin API (e.g. Okta, Azure AD, Duo) — pass it as "
                    f"mfa_enrollment_data=[{{'user': ..., 'methods': [...]}}, ...]. Unauthenticated "
                    f"network probing of {target} cannot determine per-user MFA enrollment.",
            error="requires_credentials: no MFA enrollment/policy data supplied",
        )

    findings: list[Finding] = []
    no_mfa = 0
    weak_only = 0
    for entry in data:
        user = str(entry.get("user", "unknown"))
        methods = [str(m).lower() for m in (entry.get("methods") or [])]
        if not methods:
            no_mfa += 1
            findings.append(Finding(
                title=f"User has no MFA method enrolled: {user}",
                severity="high", confidence="certain",
                affected_asset=str(target),
                evidence=f"user={user}, methods=[] (from supplied enrollment data)",
                remediation="Require MFA enrollment for all accounts before granting access.",
                tool=tool_name,
                references=["CWE-308"],
            ))
        elif methods and all(m in _WEAK_METHODS for m in methods):
            weak_only += 1
            findings.append(Finding(
                title=f"User relies solely on SMS/voice MFA: {user}",
                severity="medium", confidence="certain",
                affected_asset=str(target),
                evidence=f"user={user}, methods={methods}",
                remediation="Migrate users off SMS/voice-only MFA to TOTP/WebAuthn/push, which resist SIM-swap attacks.",
                tool=tool_name,
                references=["CWE-308"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Real analysis of {len(data)} supplied MFA enrollment record(s) for {target}: "
                f"{no_mfa} with no MFA, {weak_only} SMS/voice-only.",
        metadata={"total_users": len(data), "no_mfa_count": no_mfa, "weak_only_count": weak_only},
    )


tool_registry.register("iam.mfa_reviews", run, metadata={
    "name": "iam.mfa_reviews",
    "domain": "iam",
    "status": "completed",
    "description": "Real analysis of supplied MFA enrollment data (no-MFA / SMS-only users); requires "
                    "IdP-exported enrollment data since this isn't network-probeable",
    "parameters": {
        "target": "The identity provider / tenant the enrollment data relates to",
        "mfa_enrollment_data": "List of {user, methods} records exported from the IdP's admin API",
    },
})
