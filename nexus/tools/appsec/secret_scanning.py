#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec.secret_scanning
Domain: appsec
Secret and credential scanning for source code, config files, and git repositories.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry


SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "github_oauth": re.compile(r"(?i)github[_-]?token['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9]{20}['\"]?"),
    "private_key": re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "api_key": re.compile(r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9]{20,64}['\"]?"),
    "password": re.compile(r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^\s]{4,}['\"]?"),
    "generic_secret": re.compile(r"(?i)(secret|token|credential)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=_-]{10,}['\"]?"),
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9]{32,}"),
    "azure_key": re.compile(r"(?i)azure[_-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9]{32,}['\"]?"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "heroku_api_key": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
}

EXCLUDED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3"}
EXCLUDED_DIRS = {".git", ".svn", "node_modules", ".venv", "__pycache__", "vendor", "dist", "build"}


def _scan_file(filepath: str, max_size_mb: int = 10) -> list[Finding]:
    """Scan a single file for secrets."""
    findings = []
    try:
        size = os.path.getsize(filepath)
        if size > max_size_mb * 1024 * 1024:
            return [Finding(
                title=f"Large file skipped: {filepath}",
                severity="info",
                confidence="certain",
                affected_asset=filepath,
                evidence=f"File size: {size} bytes exceeds {max_size_mb}MB limit",
                remediation="Review large files separately if necessary.",
                tool="appsec.secret_scanning",
            )]

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = pattern.findall(line)
                    for match in matches:
                        sev = "critical" if secret_type in ("aws_secret_key", "private_key", "password") else \
                              "high" if secret_type in ("aws_access_key", "github_token", "openai_api_key") else "medium"
                        findings.append(Finding(
                            title=f"Secret detected: {secret_type}",
                            severity=sev,
                            confidence="high",
                            affected_asset=filepath,
                            evidence=f"Line {line_num}: {line[:100].strip()}...",
                            remediation="Remove secret from code. Use environment variables or secret management.",
                            tool="appsec.secret_scanning",
                            references=["CWE-798", "CWE-259"],
                        ))
    except Exception as e:
        findings.append(Finding(
            title="File scan error",
            severity="low",
            confidence="certain",
            affected_asset=filepath,
            evidence=str(e)[:100],
            remediation="Verify file is readable text.",
            tool="appsec.secret_scanning",
        ))
    return findings


def _scan_directory(dirpath: str, max_size_mb: int = 10) -> tuple[list[Finding], int]:
    """Recursively scan a directory for secrets."""
    all_findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in EXCLUDED_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                file_findings = _scan_file(fpath, max_size_mb)
                all_findings.extend(file_findings)
                if any(f.title != "Large file skipped: " + fpath for f in file_findings):
                    files_scanned += 1
            except Exception:
                pass
    return all_findings, files_scanned


def run(
    target: str,
    max_size_mb: int = 10,
    exclude_patterns: list[str] | None = None,
    **kwargs: Any,
) -> dict:
    """Perform secret scanning against files or directory.

    Parameters
    ----------
    target : str
        Path to file, directory, or git repository to scan.
    max_size_mb : int
        Skip files larger than this size in MB.
    exclude_patterns : list[str], optional
        Additional glob patterns to exclude.
    """
    path = target.strip()
    if not path:
        return tool_result("appsec.secret_scanning", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []

    if not os.path.exists(path):
        return tool_result(
            "appsec.secret_scanning", target,
            status=STATUS_NO_FINDINGS,
            error=f"Path not found: {path}",
        )

    files_scanned = 0
    secrets_found = 0

    if os.path.isfile(path):
        findings.extend(_scan_file(path, max_size_mb))
        files_scanned = 1
    elif os.path.isdir(path):
        dir_findings, files_scanned = _scan_directory(path, max_size_mb)
        findings.extend(dir_findings)

    secrets_found = sum(1 for f in findings if "Secret detected" in f.title)

    return tool_result(
        "appsec.secret_scanning", target,
        status=STATUS_COMPLETED if secrets_found > 0 else STATUS_NO_FINDINGS,
        findings=findings,
        summary=f"Scanned {files_scanned} files, found {secrets_found} potential secrets in {path}",
        metadata={"files_scanned": files_scanned, "secrets_found": secrets_found},
    )


tool_registry.register("appsec.secret_scanning", run, metadata={
    "name": "appsec.secret_scanning",
    "domain": "appsec",
    "status": "completed",
    "description": "Secret and credential scanning for source code and config files",
    "parameters": {
        "target": "Path to file or directory to scan",
        "max_size_mb": "Skip files larger than this size (default: 10MB)",
        "exclude_patterns": "Additional glob patterns to exclude",
    },
})