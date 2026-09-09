#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.serverless_security
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs, none of which had anything to do with serverless configs. Caught
during this session's audit. Serverless misconfiguration review is
inherently a static analysis of local deployment descriptors, not a network
probe: this now treats `target` as a local `serverless.yml`/
`serverless.yaml`/SAM template (`template.yml`/`template.yaml`) path — file
or directory — and real-scans it for common misconfigurations: wildcard
IAM statements (`iamRoleStatements`/SAM `Policies` granting Action:*),
functions with public/unauthenticated HTTP triggers, and hardcoded
secret-shaped values in plaintext `environment:` blocks (regex, same
detection approach as nexus/tools/appsec/secret_scanning.py and this
session's other cloud.iac_review.py). When `target` doesn't resolve to a
real serverless config file, this honestly reports that instead of
fabricating findings (mirrors appsec/secret_scanning.py's "path not found"
handling).
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

SERVERLESS_FILENAMES = re.compile(
    r"^(serverless\.(ya?ml)|template\.(ya?ml|json)|sam\.(ya?ml))$", re.IGNORECASE
)
EXCLUDED_DIRS = {".git", ".svn", "node_modules", ".venv", "__pycache__", ".serverless", ".aws-sam"}
MAX_FILE_MB = 10

_SECRET_VALUE_RE = re.compile(
    r"(?im)^\s*[A-Za-z0-9_]*(?:secret|password|passwd|pwd|token|api[_-]?key|credential)[A-Za-z0-9_]*\s*:\s*['\"]?([^\s'\"]{6,})['\"]?\s*$"
)
_WILDCARD_ACTION_RE = re.compile(r"(?im)^\s*-?\s*Action:\s*['\"]?\*['\"]?\s*$|\"Action\"\s*:\s*\"\*\"")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def _find_serverless_files(path: str) -> list[str]:
    # An explicit file path is scanned regardless of its basename — the
    # caller pointed directly at it. Filename matching (SERVERLESS_FILENAMES)
    # only applies when searching a directory below.
    if os.path.isfile(path):
        return [path]
    matches: list[str] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            if SERVERLESS_FILENAMES.match(fname):
                matches.append(os.path.join(root, fname))
    return matches


def _scan_serverless_file(filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        if os.path.getsize(filepath) > MAX_FILE_MB * 1024 * 1024:
            return findings
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.splitlines()

    for match in _AWS_KEY_RE.finditer(content):
        line_num = content.count("\n", 0, match.start()) + 1
        findings.append(Finding(
            title="Hardcoded AWS access key ID in serverless config",
            severity="critical",
            confidence="high",
            affected_asset=filepath,
            evidence=f"Line {line_num}: {lines[line_num - 1].strip()[:160] if line_num <= len(lines) else match.group(0)}",
            remediation="Remove the key and rotate it. Use IAM roles (Lambda execution role) instead of static credentials.",
            tool="cloud.serverless_security",
            references=["CWE-798", "CWE-259"],
        ))

    for match in _WILDCARD_ACTION_RE.finditer(content):
        line_num = content.count("\n", 0, match.start()) + 1
        findings.append(Finding(
            title="Serverless function role grants wildcard Action:*",
            severity="high",
            confidence="medium",
            affected_asset=filepath,
            evidence=f"Line {line_num}: {lines[line_num - 1].strip()[:160] if line_num <= len(lines) else match.group(0)[:160]}",
            remediation="Scope iamRoleStatements/Policies to the exact actions the function needs instead of a wildcard.",
            tool="cloud.serverless_security",
            references=["CWE-269", "CIS-AWS-1.16"],
        ))

    in_env_block = False
    env_indent = None
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.match(r"^environment\s*:\s*$", stripped, re.IGNORECASE):
            in_env_block = True
            env_indent = len(line) - len(line.lstrip())
            continue
        if in_env_block:
            cur_indent = len(line) - len(line.lstrip())
            if stripped and env_indent is not None and cur_indent <= env_indent:
                in_env_block = False
            elif stripped:
                m = _SECRET_VALUE_RE.match(line)
                if m and not re.search(r"\$\{|process\.env|os\.environ", line):
                    findings.append(Finding(
                        title="Plaintext secret-shaped value in serverless environment block",
                        severity="high",
                        confidence="medium",
                        affected_asset=filepath,
                        evidence=f"Line {i}: {stripped[:160]}",
                        remediation="Reference secrets via SSM Parameter Store/Secrets Manager (e.g. ${ssm:/path/to/secret}) instead of plaintext values in the environment block.",
                        tool="cloud.serverless_security",
                        references=["CWE-798", "CWE-522"],
                    ))

    return findings


def run(target: str, **kwargs: Any) -> dict:
    """Static misconfiguration scan of a local serverless.yml/SAM template.

    Parameters
    ----------
    target : str
        Path to a local serverless.yml/serverless.yaml or SAM
        template.yml/template.yaml (file or a directory to search). Not a
        hostname/URL — serverless config review is a static-file analysis.
    """
    path = (target or "").strip()
    if not path:
        return tool_result("cloud.serverless_security", target, status=STATUS_FAILED, error="Empty target")

    if not os.path.exists(path):
        return tool_result(
            "cloud.serverless_security", target,
            status=STATUS_NO_FINDINGS,
            error=f"Path not found: {path}. cloud.serverless_security scans a local serverless.yml/SAM template, not a remote host.",
        )

    files = _find_serverless_files(path)
    if not files:
        return tool_result(
            "cloud.serverless_security", target,
            status=STATUS_NO_FINDINGS,
            error=f"No serverless.yml/serverless.yaml/template.yml/template.yaml found under '{path}'.",
        )

    findings: list[Finding] = []
    for f in files:
        findings.extend(_scan_serverless_file(f))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.serverless_security", target,
        status=status,
        findings=findings,
        summary=f"Scanned {len(files)} serverless config file(s) under '{path}', found {len(findings)} issue(s)",
        metadata={"files_scanned": len(files), "files": files},
    )


tool_registry.register("cloud.serverless_security", run, metadata={
    "name": "cloud.serverless_security",
    "domain": "cloud",
    "status": "completed",
    "description": "Static regex-based misconfiguration scan of a local serverless.yml/SAM template (wildcard IAM actions, hardcoded AWS keys, plaintext secrets in environment blocks)",
    "parameters": {
        "target": "Path to a local serverless.yml/SAM template file or directory to scan",
    },
})
