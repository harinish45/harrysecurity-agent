#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.azure_assessment
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs, none of which had anything to do with Azure. Caught during this
session's audit. requirements.txt does not pin azure-identity/azure-mgmt-*,
so there is no Azure SDK to import (unlike boto3 for AWS, which
nexus/tools/cloud/aws_review.py uses directly). What *is* achievable
honestly without adding new dependencies is shelling out to the Azure CLI
(`az`), when a caller has it installed and logged in, exactly the way
nexus/agents/offensive/digital_twin_agent.py shells out to `docker`: check
for the CLI on PATH, make one real cheap call (`az account show`) to confirm
it's actually authenticated, and only then run real read-only checks
(`az storage account list` for public blob access, `az network nsg list`
for 0.0.0.0/0 inbound rules). No `az` CLI on PATH -> STATUS_UNAVAILABLE. CLI
present but not logged in -> STATUS_REQUIRES_CREDENTIALS. Never a fabricated
Azure resource finding.
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


def _az_json(args: list[str], timeout: int = _TIMEOUT):
    proc = subprocess.run(
        ["az"] + args + ["--output", "json"],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        return None, proc.stderr.strip()[:500]
    try:
        return json.loads(proc.stdout or "null"), None
    except json.JSONDecodeError as exc:
        return None, f"Could not parse az output: {exc}"


def _check_public_storage_accounts() -> list[Finding]:
    findings: list[Finding] = []
    accounts, _err = _az_json(["storage", "account", "list"])
    for account in accounts or []:
        if account.get("allowBlobPublicAccess"):
            name = account.get("name", "unknown")
            findings.append(Finding(
                title=f"Storage account '{name}' allows public blob access",
                severity="high",
                confidence="certain",
                affected_asset=f"azure-storage://{name}",
                evidence="allowBlobPublicAccess = true",
                remediation="Set allowBlobPublicAccess to false at the storage account level and use SAS tokens or private endpoints for controlled access.",
                tool="cloud.azure_assessment",
                references=["CWE-284", "CIS-Azure-3.7"],
            ))
    return findings


def _check_open_nsg_rules() -> list[Finding]:
    findings: list[Finding] = []
    nsgs, _err = _az_json(["network", "nsg", "list"])
    for nsg in nsgs or []:
        nsg_name = nsg.get("name", "unknown")
        for rule in nsg.get("securityRules", []) or []:
            if (
                str(rule.get("access", "")).lower() == "allow"
                and str(rule.get("direction", "")).lower() == "inbound"
                and str(rule.get("sourceAddressPrefix", "")) in ("*", "0.0.0.0/0", "Internet", "Any")
            ):
                findings.append(Finding(
                    title=f"NSG '{nsg_name}' allows inbound access from the internet",
                    severity="high",
                    confidence="high",
                    affected_asset=f"azure-nsg://{nsg_name}",
                    evidence=f"Rule '{rule.get('name', '?')}': sourceAddressPrefix={rule.get('sourceAddressPrefix')}, destinationPortRange={rule.get('destinationPortRange', '?')}",
                    remediation="Restrict sourceAddressPrefix to known CIDR ranges instead of Any/Internet/0.0.0.0/0.",
                    tool="cloud.azure_assessment",
                    references=["CWE-284", "CIS-Azure-6.2"],
                ))
    return findings


def run(target: str = "subscription", **kwargs: Any) -> dict:
    """Perform a read-only Azure security assessment via the Azure CLI.

    Parameters
    ----------
    target : str
        Target to assess (typically "subscription" for the active az CLI
        subscription context).
    """
    if not shutil.which("az"):
        return tool_result(
            "cloud.azure_assessment", target,
            status=STATUS_UNAVAILABLE,
            summary="Azure assessment requires the Azure CLI (`az`), which is not on PATH",
            error="az executable not found on PATH (pip/install: https://aka.ms/InstallAzureCli, or `pip install azure-identity azure-mgmt-resource` for SDK-based access)",
        )

    try:
        proc = subprocess.run(
            ["az", "account", "show", "--output", "json"],
            capture_output=True, text=True, timeout=_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return tool_result("cloud.azure_assessment", target, status=STATUS_UNAVAILABLE, error=str(exc))

    if proc.returncode != 0:
        return tool_result(
            "cloud.azure_assessment", target,
            status=STATUS_REQUIRES_CREDENTIALS,
            error="Azure CLI is not authenticated. Run `az login` (or configure AZURE_CLIENT_ID/AZURE_TENANT_ID/AZURE_CLIENT_SECRET for a service principal).",
        )

    try:
        account = json.loads(proc.stdout)
    except json.JSONDecodeError:
        account = {}
    subscription_id = account.get("id", "unknown")
    subscription_name = account.get("name", "unknown")

    findings: list[Finding] = []
    findings.extend(_check_public_storage_accounts())
    findings.extend(_check_open_nsg_rules())

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.azure_assessment", target,
        status=status,
        findings=findings,
        summary=f"Assessed Azure subscription '{subscription_name}' ({subscription_id}); {len(findings)} issue(s) found",
        metadata={"subscription_id": subscription_id, "subscription_name": subscription_name},
    )


tool_registry.register("cloud.azure_assessment", run, metadata={
    "name": "cloud.azure_assessment",
    "domain": "cloud",
    "status": "completed",
    "description": "Real Azure-CLI-based read-only assessment (public storage accounts, internet-open NSG rules) of the active `az` subscription; requires az CLI installed and logged in",
    "parameters": {
        "target": "Target to assess (subscription for the active az CLI context)",
    },
})
