#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.gcp_review
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs, none of which had anything to do with GCP. Caught during this
session's audit. requirements.txt does not pin google-cloud-*/google-auth,
so there is no GCP SDK to import (unlike boto3 for AWS, which
nexus/tools/cloud/aws_review.py uses directly). What *is* achievable
honestly without adding new dependencies is shelling out to the gcloud CLI,
the same pattern nexus/agents/offensive/digital_twin_agent.py uses for
`docker`: check for the CLI on PATH, make one real cheap call
(`gcloud auth list`) to confirm there's an active authenticated account, and
only then run real read-only checks (`gcloud compute firewall-rules list`
for 0.0.0.0/0-open ingress, `gsutil iam get` for allUsers-readable storage
buckets). No `gcloud` CLI on PATH -> STATUS_UNAVAILABLE. CLI present but no
active account -> STATUS_REQUIRES_CREDENTIALS. Never a fabricated GCP
resource finding.
"""
from __future__ import annotations

import json
import shutil
import subprocess
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

_TIMEOUT = 30


def _gcloud_json(args: list[str], timeout: int = _TIMEOUT):
    proc = subprocess.run(
        ["gcloud"] + args + ["--format", "json"],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        return None, proc.stderr.strip()[:500]
    try:
        return json.loads(proc.stdout or "null"), None
    except json.JSONDecodeError as exc:
        return None, f"Could not parse gcloud output: {exc}"


def _check_open_firewall_rules() -> list[Finding]:
    findings: list[Finding] = []
    rules, _err = _gcloud_json(["compute", "firewall-rules", "list"])
    for rule in rules or []:
        if str(rule.get("direction", "")).upper() != "INGRESS":
            continue
        source_ranges = rule.get("sourceRanges", []) or []
        if "0.0.0.0/0" in source_ranges and str(rule.get("disabled", False)) not in ("True", "true", True):
            name = rule.get("name", "unknown")
            allowed = rule.get("allowed", [])
            findings.append(Finding(
                title=f"Firewall rule '{name}' allows ingress from 0.0.0.0/0",
                severity="high",
                confidence="certain",
                affected_asset=f"gcp-firewall://{name}",
                evidence=f"sourceRanges={source_ranges}, allowed={allowed}",
                remediation="Restrict sourceRanges to known CIDR blocks instead of 0.0.0.0/0; use Identity-Aware Proxy or a bastion for admin access.",
                tool="cloud.gcp_review",
                references=["CWE-284", "CIS-GCP-3.6"],
            ))
    return findings


def _check_public_buckets() -> list[Finding]:
    findings: list[Finding] = []
    buckets, _err = _gcloud_json(["storage", "buckets", "list"])
    for bucket in buckets or []:
        name = bucket.get("name") or bucket.get("id", "unknown")
        try:
            proc = subprocess.run(
                ["gcloud", "storage", "buckets", "get-iam-policy", f"gs://{name}", "--format", "json"],
                capture_output=True, text=True, timeout=_TIMEOUT,
            )
            if proc.returncode != 0:
                continue
            policy = json.loads(proc.stdout or "{}")
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            continue
        for binding in policy.get("bindings", []) or []:
            members = binding.get("members", []) or []
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                findings.append(Finding(
                    title=f"Storage bucket '{name}' is publicly accessible",
                    severity="high",
                    confidence="certain",
                    affected_asset=f"gcp-bucket://{name}",
                    evidence=f"IAM binding role={binding.get('role')} grants access to {[m for m in members if m in ('allUsers', 'allAuthenticatedUsers')]}",
                    remediation="Remove allUsers/allAuthenticatedUsers from the bucket IAM policy; use signed URLs or scoped service-account access instead.",
                    tool="cloud.gcp_review",
                    references=["CWE-284", "CIS-GCP-5.1"],
                ))
    return findings


def run(target: str = "project", **kwargs: Any) -> dict:
    """Perform a read-only GCP security review via the gcloud CLI.

    Parameters
    ----------
    target : str
        Target to assess (typically "project" for the active gcloud CLI
        project context).
    """
    if not shutil.which("gcloud"):
        return tool_result(
            "cloud.gcp_review", target,
            status=STATUS_UNAVAILABLE,
            summary="GCP review requires the gcloud CLI, which is not on PATH",
            error="gcloud executable not found on PATH (https://cloud.google.com/sdk/docs/install, or `pip install google-cloud-storage google-cloud-compute google-auth` for SDK-based access)",
        )

    try:
        accounts, err = _gcloud_json(["auth", "list"])
    except (subprocess.TimeoutExpired, OSError) as exc:
        return tool_result("cloud.gcp_review", target, status=STATUS_UNAVAILABLE, error=str(exc))

    active_accounts = [a for a in (accounts or []) if a.get("status") == "ACTIVE"]
    if not active_accounts:
        return tool_result(
            "cloud.gcp_review", target,
            status=STATUS_REQUIRES_CREDENTIALS,
            error=err or "No active gcloud account. Run `gcloud auth login` (or set GOOGLE_APPLICATION_CREDENTIALS for a service account).",
        )

    project_info, _err = _gcloud_json(["config", "get-value", "project"])
    project_id = project_info if isinstance(project_info, str) else (project_info or "unknown")

    findings: list[Finding] = []
    findings.extend(_check_open_firewall_rules())
    findings.extend(_check_public_buckets())

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.gcp_review", target,
        status=status,
        findings=findings,
        summary=f"Reviewed GCP project '{project_id}' as {active_accounts[0].get('account', 'unknown')}; {len(findings)} issue(s) found",
        metadata={"project_id": project_id, "active_account": active_accounts[0].get("account", "unknown")},
    )


tool_registry.register("cloud.gcp_review", run, metadata={
    "name": "cloud.gcp_review",
    "domain": "cloud",
    "status": "completed",
    "description": "Real gcloud-CLI-based read-only review (0.0.0.0/0 firewall rules, public storage buckets) of the active gcloud project; requires gcloud CLI installed and authenticated",
    "parameters": {
        "target": "Target to assess (project for the active gcloud CLI context)",
    },
})
