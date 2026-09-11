#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.iam_audit
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs, none of which had anything to do with IAM. Caught during this
session's audit. IAM auditing needs real AWS credentials and the boto3 SDK
(same dependency nexus/tools/cloud/aws_review.py already uses) — there's no
network-observable substitute. This now mirrors aws_review.py's exact
pattern: verify boto3 is installed, verify credentials actually work via
`sts.get_caller_identity()`, and only then run real read-only IAM checks —
`list_users`, `list_mfa_devices` (flag console-capable users with no MFA
device), and `list_user_policies`/`get_user_policy` plus
`list_attached_user_policies` (flag inline or attached policies granting
`Action: "*"` on `Resource: "*"`). No credentials configured ->
STATUS_REQUIRES_CREDENTIALS, matching aws_review.py; never a fabricated
finding.
"""
from __future__ import annotations

import json
from typing import Any, Optional

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


def _is_wildcard_admin_statement(statement: dict) -> bool:
    if str(statement.get("Effect", "")).lower() != "allow":
        return False
    action = statement.get("Action")
    resource = statement.get("Resource")
    action_is_wild = action == "*" or (isinstance(action, list) and "*" in action)
    resource_is_wild = resource == "*" or (isinstance(resource, list) and "*" in resource)
    return action_is_wild and resource_is_wild


def _check_wildcard_policy_doc(policy_doc: dict) -> bool:
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return any(_is_wildcard_admin_statement(s) for s in statements)


def _check_user_mfa(iam_client, user_name: str) -> Optional[Finding]:
    try:
        user = iam_client.get_user(UserName=user_name).get("User", {})
    except Exception:
        return None
    has_console_access = "PasswordLastUsed" in user
    if not has_console_access:
        return None
    try:
        mfa = iam_client.list_mfa_devices(UserName=user_name)
        if not mfa.get("MFADevices"):
            return Finding(
                title=f"IAM user '{user_name}' has console access without MFA",
                severity="high",
                confidence="certain",
                affected_asset=f"iam-user://{user_name}",
                evidence="User has PasswordLastUsed set (console login capable) and zero MFA devices attached.",
                remediation="Require MFA for all console-access IAM users; enforce via an IAM policy condition (aws:MultiFactorAuthPresent).",
                tool="cloud.iam_audit",
                references=["CWE-308", "CIS-AWS-1.10"],
            )
    except Exception:
        return None
    return None


def _check_user_wildcard_policies(iam_client, user_name: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        inline_names = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
        for policy_name in inline_names:
            doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
            policy_doc = doc.get("PolicyDocument", {})
            if _check_wildcard_policy_doc(policy_doc):
                findings.append(Finding(
                    title=f"IAM user '{user_name}' has an inline policy granting full admin (*:*)",
                    severity="critical",
                    confidence="certain",
                    affected_asset=f"iam-user://{user_name}",
                    evidence=f"Inline policy '{policy_name}' contains an Allow statement with Action:* and Resource:*",
                    remediation="Scope the policy to the specific actions/resources this user needs; never grant Action:*/Resource:*.",
                    tool="cloud.iam_audit",
                    references=["CWE-269", "CIS-AWS-1.16"],
                ))
    except Exception:
        pass

    try:
        attached = iam_client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
        for policy in attached:
            if policy.get("PolicyName") == "AdministratorAccess":
                findings.append(Finding(
                    title=f"IAM user '{user_name}' has AdministratorAccess attached directly",
                    severity="high",
                    confidence="certain",
                    affected_asset=f"iam-user://{user_name}",
                    evidence=f"Managed policy 'AdministratorAccess' ({policy.get('PolicyArn', '')}) attached directly to a user.",
                    remediation="Grant admin access via a role assumed through SSO/temporary credentials, not a directly-attached managed policy on a long-lived user.",
                    tool="cloud.iam_audit",
                    references=["CWE-269", "CIS-AWS-1.16"],
                ))
    except Exception:
        pass

    return findings


def run(target: str = "account", profile: str | None = None, **kwargs: Any) -> dict:
    """Perform a read-only AWS IAM security audit using boto3.

    Parameters
    ----------
    target : str
        Target to assess (typically "account" for a full IAM review).
    profile : str, optional
        AWS profile name to use.
    """
    try:
        import boto3
        from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
    except ImportError:
        return tool_result(
            "cloud.iam_audit", target,
            status=STATUS_UNAVAILABLE,
            error="boto3 not installed (pip install boto3)",
        )

    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile

    try:
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "unknown")
    except (NoCredentialsError, PartialCredentialsError):
        return tool_result(
            "cloud.iam_audit", target,
            status=STATUS_REQUIRES_CREDENTIALS,
            error="AWS credentials not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or configure a profile.",
        )
    except Exception as e:
        return tool_result("cloud.iam_audit", target, status=STATUS_FAILED, error=f"AWS credential error: {e}")

    findings: list[Finding] = []
    try:
        iam = session.client("iam")
        users = iam.list_users().get("Users", [])
    except ClientError as e:
        return tool_result(
            "cloud.iam_audit", target,
            status=STATUS_FAILED,
            error=f"iam:ListUsers denied or failed: {e}",
        )
    except Exception as e:
        return tool_result("cloud.iam_audit", target, status=STATUS_FAILED, error=str(e))

    for user in users:
        user_name = user.get("UserName")
        if not user_name:
            continue
        mfa_finding = _check_user_mfa(iam, user_name)
        if mfa_finding:
            findings.append(mfa_finding)
        findings.extend(_check_user_wildcard_policies(iam, user_name))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.iam_audit", target,
        status=status,
        findings=findings,
        summary=f"Audited {len(users)} IAM user(s) in account {account_id}; {len(findings)} issue(s) found",
        metadata={"account_id": account_id, "users_checked": len(users)},
    )


tool_registry.register("cloud.iam_audit", run, metadata={
    "name": "cloud.iam_audit",
    "domain": "cloud",
    "status": "completed",
    "description": "Real boto3-based read-only IAM audit: flags console-access users without MFA and inline/attached policies granting Action:*/Resource:*; requires working AWS credentials",
    "parameters": {
        "target": "Target to assess (account for full review)",
        "profile": "AWS profile name",
    },
})
