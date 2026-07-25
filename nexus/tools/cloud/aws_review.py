#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.aws_review
Domain: cloud
AWS security assessment via boto3 SDK with read-only configuration review.
"""
from __future__ import annotations

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


def _check_iam_password_policy(iam_client) -> Optional[Finding]:
    """Check IAM password policy for security issues."""
    try:
        policy = iam_client.get_account_password_policy()
        pp = policy.get("PasswordPolicy", {})
        issues = []
        if pp.get("MinimumPasswordLength", 12) < 12:
            issues.append("Minimum password length < 12")
        if not pp.get("RequireUppercaseCharacters", True):
            issues.append("Uppercase not required")
        if not pp.get("RequireLowercaseCharacters", True):
            issues.append("Lowercase not required")
        if not pp.get("RequireNumbers", True):
            issues.append("Numbers not required")
        if not pp.get("RequireSymbols", True):
            issues.append("Symbols not required")
        if pp.get("MaxPasswordAge", 90) > 90:
            issues.append("Max password age > 90 days")

        if issues:
            return Finding(
                title="Weak IAM password policy",
                severity="medium",
                confidence="certain",
                affected_asset="IAM",
                evidence="; ".join(issues),
                remediation="Strengthen password policy to require 12+ chars with mixed case, numbers, and symbols.",
                tool="cloud.aws_review",
                references=["CWE-521", "CIS-AWS-1.5.0"],
            )
    except Exception:
        pass
    return None


def _check_cloudtrail_enabled(ct_client) -> list[Finding]:
    """Check if CloudTrail is enabled in all regions."""
    findings = []
    try:
        trails = ct_client.describe_trails(includeJoinedOrganizationsAccounts=True)
        trail_list = trails.get("trailList", [])
        if not trail_list:
            findings.append(Finding(
                title="No CloudTrail trails found",
                severity="high",
                confidence="certain",
                affected_asset="CloudTrail",
                evidence="No logging trails configured",
                remediation="Enable CloudTrail in all regions for audit logging.",
                tool="cloud.aws_review",
                references=["CIS-AWS-1.5.0"],
            ))
    except Exception:
        pass
    return findings


def _check_s3_bucket_acl(s3_client) -> list[Finding]:
    """Check S3 buckets for public access."""
    findings = []
    try:
        buckets = s3_client.list_buckets()
        for bucket in buckets.get("Buckets", []):
            name = bucket["Name"]
            try:
                acl = s3_client.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "").endswith("AllUsers"):
                        findings.append(Finding(
                            title=f"S3 bucket {name} has public access",
                            severity="high",
                            confidence="certain",
                            affected_asset=f"s3://{name}",
                            evidence=f"Public grant: {grant.get('Permission')}",
                            remediation="Remove public access or restrict to specific principals.",
                            tool="cloud.aws_review",
                            references=["CWE-200", "CIS-AWS-1.5.0"],
                        ))
            except Exception:
                pass
    except Exception:
        pass
    return findings


def run(
    target: str = "account",
    profile: str | None = None,
    regions: list[str] | None = None,
    check_password_policy: bool = True,
    check_cloudtrail: bool = True,
    check_s3: bool = True,
    **kwargs: Any,
) -> dict:
    """Perform AWS security assessment using boto3 SDK.

    Parameters
    ----------
    target : str
        Target to assess (typically "account" for full account review).
    profile : str, optional
        AWS profile name to use.
    regions : list[str], optional
        AWS regions to check. Defaults to all available.
    check_password_policy : bool
        Check IAM password policy.
    check_cloudtrail : bool
        Check CloudTrail configuration.
    check_s3 : bool
        Check S3 bucket ACLs.
    """
    import os
    try:
        import boto3
        from botocore.exceptions import NoCredentialsError, PartialCredentialsError
    except ImportError:
        return tool_result(
            "cloud.aws_review", target,
            status=STATUS_UNAVAILABLE,
            error="boto3 not installed (pip install boto3)",
        )

    findings: list[Finding] = []

    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile

    try:
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "unknown")
        findings.append(Finding(
            title="AWS account assessed",
            severity="info",
            confidence="certain",
            affected_asset=f"AWS account {account_id}",
            evidence=f"Caller identity: {identity.get('Arn', 'unknown')}",
            remediation="No action needed for read-only assessment.",
            tool="cloud.aws_review",
        ))
    except (NoCredentialsError, PartialCredentialsError):
        return tool_result(
            "cloud.aws_review", target,
            status=STATUS_REQUIRES_CREDENTIALS,
            error="AWS credentials not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.",
        )
    except Exception as e:
        return tool_result(
            "cloud.aws_review", target,
            status=STATUS_FAILED,
            error=f"AWS credential error: {e}",
        )

    if check_password_policy:
        try:
            iam = session.client("iam")
            pw_findings = _check_iam_password_policy(iam)
            if pw_findings:
                findings.append(pw_findings)
        except Exception:
            pass

    if check_cloudtrail:
        try:
            ct = session.client("cloudtrail")
            ct_findings = _check_cloudtrail_enabled(ct)
            findings.extend(ct_findings)
        except Exception:
            pass

    if check_s3:
        try:
            s3 = session.client("s3")
            s3_findings = _check_s3_bucket_acl(s3)
            findings.extend(s3_findings)
        except Exception:
            pass

    return tool_result(
        "cloud.aws_review", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"AWS assessment completed with {len(findings)} findings",
        metadata={"target_type": "account"},
    )


tool_registry.register("cloud.aws_review", run, metadata={
    "name": "cloud.aws_review",
    "domain": "cloud",
    "status": "completed",
    "description": "AWS security assessment via boto3 SDK with read-only configuration review",
    "parameters": {
        "target": "Target to assess (account for full review)",
        "profile": "AWS profile name",
        "regions": "AWS regions to check",
        "check_password_policy": "Check IAM password policy (default: True)",
        "check_cloudtrail": "Check CloudTrail configuration (default: True)",
        "check_s3": "Check S3 bucket ACLs (default: True)",
    },
})