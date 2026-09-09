#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec.cicd_security
Domain: appsec
Real regex-based review of local CI/CD config files (.github/workflows/*.yml,
.gitlab-ci.yml, Jenkinsfile) for common misconfigurations: plaintext secrets
in env vars, `pull_request_target` combined with an untrusted PR-head
checkout, and overly broad `permissions: write-all`.

Previously this ignored `target` as a repo/config path entirely and did a
bare DNS resolve + HTTP GET on "/" (byte-for-byte identical to 19 other stub
tools) — caught during this session's audit. CI/CD config review is a local
file operation, not a network-observable one; `target` is now honestly
reinterpreted as a local path. A non-local-path target degrades to
STATUS_OUT_OF_SCOPE instead of fabricating results.
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
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_ENV_SECRET_RE = re.compile(
    r"(?im)^[ \t]*[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY)[A-Za-z0-9_]*\s*:\s*"
    r"(?!\$\{\{)([\"']?)([^\s\"'{][^\r\n]{3,})\1\s*$"
)
_PR_TARGET_RE = re.compile(r"pull_request_target")
_UNTRUSTED_CHECKOUT_RE = re.compile(r"ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head")
_WRITE_ALL_RE = re.compile(r"(?im)^[ \t]*permissions\s*:\s*write-all\s*$")

_CI_FILENAMES = {"Jenkinsfile", ".gitlab-ci.yml"}


def _find_ci_files(path: str) -> list[str]:
    ci_files: list[str] = []
    workflows_dir = os.path.join(path, ".github", "workflows")
    if os.path.isdir(workflows_dir):
        for fname in sorted(os.listdir(workflows_dir)):
            if fname.endswith((".yml", ".yaml")):
                ci_files.append(os.path.join(workflows_dir, fname))
    for fname in _CI_FILENAMES:
        candidate = os.path.join(path, fname)
        if os.path.isfile(candidate):
            ci_files.append(candidate)
    return ci_files


def _review_file(path: str, tool_name: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return findings

    m = _ENV_SECRET_RE.search(text)
    if m:
        findings.append(Finding(
            title="Possible plaintext secret in CI env var",
            severity="high",
            confidence="medium",
            affected_asset=path,
            evidence=f"Matched: {m.group(0).strip()[:120]}",
            remediation="Use the CI platform's encrypted secret store (e.g. ${{ secrets.X }}) instead of "
                         "plaintext values in the workflow file.",
            tool=tool_name,
            references=["CWE-798"],
        ))

    if _PR_TARGET_RE.search(text) and _UNTRUSTED_CHECKOUT_RE.search(text):
        findings.append(Finding(
            title="pull_request_target with untrusted PR-head checkout",
            severity="critical",
            confidence="high",
            affected_asset=path,
            evidence="Workflow triggers on pull_request_target (which runs with base-repo secrets/write "
                      "access) and checks out ${{ github.event.pull_request.head }} — untrusted PR code "
                      "runs with privileged access.",
            remediation="Avoid checking out the PR head ref under pull_request_target; use the pull_request "
                         "trigger instead, or check out only the base ref and diff manually.",
            tool=tool_name,
            references=["CWE-829", "GHSA pull_request_target guidance"],
        ))

    if _WRITE_ALL_RE.search(text):
        findings.append(Finding(
            title="Workflow grants permissions: write-all",
            severity="medium",
            confidence="high",
            affected_asset=path,
            evidence="permissions: write-all grants the GITHUB_TOKEN full write access across all scopes.",
            remediation="Scope permissions to the minimum each job/step actually needs "
                         "(e.g. contents: read, pull-requests: write).",
            tool=tool_name,
            references=["CWE-269"],
        ))

    return findings


def run(target: str, **kwargs: Any) -> dict:
    """Regex-based review of local CI/CD config files for common misconfigurations.

    Parameters
    ----------
    target : str
        Path to a repo checkout (containing .github/workflows, .gitlab-ci.yml,
        or Jenkinsfile) or directly to one such config file.
    """
    tool_name = "appsec.cicd_security"
    path = (target or "").strip()
    if not path:
        return tool_result(tool_name, target, status=STATUS_FAILED, error="Empty target")

    if not os.path.exists(path):
        return tool_result(
            tool_name, target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"{path} is not a local path — CI/CD config review requires a local repo checkout "
                    f"or config file, not a network target.",
        )

    if os.path.isfile(path):
        base = os.path.basename(path)
        ci_files = [path] if base in _CI_FILENAMES or base.endswith((".yml", ".yaml")) else []
    else:
        ci_files = _find_ci_files(path)

    if not ci_files:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"No CI/CD config files (.github/workflows/*.yml, .gitlab-ci.yml, Jenkinsfile) "
                    f"found under {path}.",
        )

    findings: list[Finding] = []
    for f in ci_files:
        findings.extend(_review_file(f, tool_name))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Regex-based CI/CD config review of {len(ci_files)} file(s) under {path}: "
                f"{len(findings)} issue(s) found.",
        metadata={"ci_files_reviewed": ci_files, "issues_found": len(findings)},
    )


tool_registry.register("appsec.cicd_security", run, metadata={
    "name": "appsec.cicd_security",
    "domain": "appsec",
    "status": "completed",
    "description": "Real regex-based review of local CI/CD config files for plaintext secrets, "
                    "pull_request_target with untrusted checkout, and permissions: write-all",
    "parameters": {
        "target": "Local path to a repo checkout or a CI config file",
    },
})
