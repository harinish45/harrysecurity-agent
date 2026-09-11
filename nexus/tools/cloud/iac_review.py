#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.iac_review
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs, none of which had anything to do with Infrastructure-as-Code. Caught
during this session's audit. IaC review is inherently a static analysis of
local files, not a network probe: this now treats `target` as a local file
or directory path and, when it resolves, real-scans every
`.tf`/`.tfvars`/`.yaml`/`.yml`/CloudFormation-JSON file it finds for common
misconfiguration patterns (open ingress to 0.0.0.0/0, wildcard IAM
Allow/Action/Resource policies, embedded AWS access keys, `public-read`
ACLs) via regex — the same static-scan approach as
nexus/tools/appsec/secret_scanning.py, just targeting infra-as-code
misconfigurations instead of secrets. When `target` is not a valid local
path, this honestly reports that rather than fabricating findings (mirrors
appsec/secret_scanning.py's own "path not found" handling).
"""
from __future__ import annotations

import os
import re
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

IAC_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json"}
EXCLUDED_DIRS = {".git", ".svn", "node_modules", ".venv", "__pycache__", "vendor", "dist", "build", ".terraform"}
MAX_FILE_MB = 10

# (pattern, title, severity, remediation, references)
_MISCONFIG_CHECKS: list[tuple[re.Pattern, str, str, str, list[str]]] = [
    (
        re.compile(r"0\.0\.0\.0/0"),
        "Ingress/egress rule open to the internet (0.0.0.0/0)",
        "high",
        "Restrict CIDR ranges to known IP ranges (VPN, bastion, load balancer) instead of 0.0.0.0/0.",
        ["CWE-284", "CIS-AWS-5.2"],
    ),
    (
        re.compile(r'"Effect"\s*:\s*"Allow"[\s\S]{0,200}?"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])[\s\S]{0,200}?"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])'),
        "IAM policy statement grants Allow *:* (full admin)",
        "critical",
        "Scope the policy to specific actions and resource ARNs; never grant Action:* Resource:* in an IAM policy.",
        ["CWE-269", "CIS-AWS-1.16"],
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Hardcoded AWS access key ID in IaC source",
        "critical",
        "Remove the key from source control and rotate it immediately. Use a secrets manager or environment-scoped credentials instead.",
        ["CWE-798", "CWE-259"],
    ),
    (
        re.compile(r"(?i)public-read(-write)?"),
        "public-read ACL configured in IaC",
        "high",
        "Do not set public-read/public-read-write ACLs on storage resources; use private ACLs plus explicit, scoped bucket policies.",
        ["CWE-284", "CIS-AWS-2.1.5"],
    ),
    (
        re.compile(r"(?i)action\s*=\s*\[?\s*\"?\*\"?\s*\]?"),
        "Terraform IAM policy statement action wildcard",
        "high",
        "Enumerate the exact IAM actions required instead of using a wildcard action.",
        ["CWE-269", "CIS-AWS-1.16"],
    ),
]


def _scan_iac_file(filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        if os.path.getsize(filepath) > MAX_FILE_MB * 1024 * 1024:
            return findings
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.splitlines()
    for pattern, title, severity, remediation, references in _MISCONFIG_CHECKS:
        for match in pattern.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            snippet = lines[line_num - 1].strip()[:160] if 0 < line_num <= len(lines) else match.group(0)[:160]
            findings.append(Finding(
                title=title,
                severity=severity,
                confidence="medium",
                affected_asset=filepath,
                evidence=f"Line {line_num}: {snippet}",
                remediation=remediation,
                tool="cloud.iac_review",
                references=references,
            ))
    return findings


def _scan_iac_directory(dirpath: str) -> tuple[list[Finding], int]:
    all_findings: list[Finding] = []
    files_scanned = 0
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in IAC_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            all_findings.extend(_scan_iac_file(fpath))
            files_scanned += 1
    return all_findings, files_scanned


def run(target: str, **kwargs: Any) -> dict:
    """Static misconfiguration scan of local Terraform/CloudFormation/YAML IaC.

    Parameters
    ----------
    target : str
        Path to a local IaC file or directory to scan (.tf, .tfvars, .yaml,
        .yml, or CloudFormation JSON). Not a hostname/URL — IaC review is a
        static-file analysis, not a network probe.
    """
    path = (target or "").strip()
    if not path:
        return tool_result("cloud.iac_review", target, status=STATUS_FAILED, error="Empty target")

    if not os.path.exists(path):
        return tool_result(
            "cloud.iac_review", target,
            status=STATUS_NO_FINDINGS,
            error=f"Path not found: {path}. cloud.iac_review scans a local IaC file/directory, not a remote host.",
        )

    if os.path.isfile(path):
        findings = _scan_iac_file(path)
        files_scanned = 1
    else:
        findings, files_scanned = _scan_iac_directory(path)

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.iac_review", target,
        status=status,
        findings=findings,
        summary=f"Scanned {files_scanned} IaC file(s) under '{path}', found {len(findings)} misconfiguration(s)",
        metadata={"files_scanned": files_scanned, "misconfigs_found": len(findings)},
    )


tool_registry.register("cloud.iac_review", run, metadata={
    "name": "cloud.iac_review",
    "domain": "cloud",
    "status": "completed",
    "description": "Static regex-based misconfiguration scan of local Terraform/CloudFormation/YAML IaC files (open ingress, wildcard IAM policy, hardcoded AWS keys, public-read ACLs)",
    "parameters": {
        "target": "Path to a local IaC file or directory to scan",
    },
})
