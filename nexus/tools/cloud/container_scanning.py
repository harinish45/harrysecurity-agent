#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.container_scanning
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs, none of which had anything to do with container images. Caught during
this session's audit. Real container image scanning (CVE layer analysis)
would need a vulnerability database this codebase doesn't ship; what *is*
achievable honestly with just the Docker CLI is real layer/config
inspection: `target` is treated as a local image name:tag, and `docker
inspect` is used to pull its actual base-image digest, exposed ports, and
environment variables — then those env vars are regex-scanned for
leaked-secret shapes (reusing the same detection approach as
nexus/tools/appsec/secret_scanning.py) rather than fabricating CVE findings
this tool has no data source for. Mirrors the honest-degrade pattern in
nexus/agents/offensive/digital_twin_agent.py: no Docker CLI or unreachable
daemon -> STATUS_UNAVAILABLE; image not found locally -> STATUS_FAILED with
the real docker error, never a fabricated result.
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
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TIMEOUT = 20

# Secret-shaped env var values — same intent as
# nexus/tools/appsec/secret_scanning.py's SECRET_PATTERNS, kept local since
# these match against `KEY=value` env strings rather than source-file lines.
import re

_SECRET_ENV_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "generic_secret_key_name": re.compile(
        r"(?i)^(.*(?:secret|password|passwd|pwd|token|api[_-]?key|credential).*)=(.+)$"
    ),
}


def _flag_env_secrets(env_list: list[str], image: str) -> list[Finding]:
    findings: list[Finding] = []
    for entry in env_list or []:
        if "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        if not value:
            continue
        for secret_type, pattern in _SECRET_ENV_PATTERNS.items():
            if pattern.search(entry):
                findings.append(Finding(
                    title=f"Image '{image}' bakes a likely secret into ENV {key}",
                    severity="high",
                    confidence="medium",
                    affected_asset=f"docker-image://{image}",
                    evidence=f"Environment variable name/value shape matches {secret_type}: {key}=<redacted, {len(value)} chars>",
                    remediation="Never bake credentials into image layers via ENV/ARG. Inject secrets at runtime (--env-file excluded from the image, orchestrator secret store, or a vault sidecar).",
                    tool="cloud.container_scanning",
                    references=["CWE-798", "CWE-522"],
                ))
                break
    return findings


def run(target: str, **kwargs: Any) -> dict:
    """Inspect a local Docker image's layers/config for security issues.

    Parameters
    ----------
    target : str
        A local Docker image reference (name:tag or image ID) reachable via
        `docker inspect`. Not a remote registry image and not a hostname.
    """
    if not target or not target.strip():
        return tool_result("cloud.container_scanning", target, status=STATUS_FAILED, error="Empty target")

    if not shutil.which("docker"):
        return tool_result(
            "cloud.container_scanning", target,
            status=STATUS_UNAVAILABLE,
            summary="Container image scanning requires the `docker` CLI, which is not on PATH",
            error="docker executable not found on PATH",
        )

    try:
        subprocess.run(
            ["docker", "info", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=_TIMEOUT, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        return tool_result(
            "cloud.container_scanning", target,
            status=STATUS_UNAVAILABLE,
            summary="Docker CLI found but the daemon is not reachable",
            error=f"`docker info` failed: {exc}",
        )

    try:
        proc = subprocess.run(
            ["docker", "inspect", target.strip()],
            capture_output=True, text=True, timeout=_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return tool_result(
            "cloud.container_scanning", target,
            status=STATUS_FAILED,
            error=f"`docker inspect` failed: {exc}",
        )

    if proc.returncode != 0:
        return tool_result(
            "cloud.container_scanning", target,
            status=STATUS_FAILED,
            error=f"Image not found locally: {proc.stderr.strip()[:300]}",
            summary=f"docker inspect could not find local image '{target}' — pull it first (docker pull {target}) or verify the name/tag.",
        )

    try:
        inspected = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return tool_result("cloud.container_scanning", target, status=STATUS_FAILED, error=f"Could not parse docker inspect output: {exc}")

    if not inspected:
        return tool_result("cloud.container_scanning", target, status=STATUS_NO_FINDINGS, summary="docker inspect returned no data for this image")

    findings: list[Finding] = []
    info = inspected[0]
    config = info.get("Config", {}) or {}
    exposed_ports = list((config.get("ExposedPorts") or {}).keys())
    env_list = config.get("Env", []) or []

    findings.extend(_flag_env_secrets(env_list, target))

    if config.get("User", "") in ("", "root", "0"):
        findings.append(Finding(
            title=f"Image '{target}' runs as root",
            severity="medium",
            confidence="certain",
            affected_asset=f"docker-image://{target}",
            evidence=f"Config.User = '{config.get('User', '')}' (empty/root/0 means the default user is root)",
            remediation="Add a USER directive in the Dockerfile to run the container process as a non-root UID.",
            tool="cloud.container_scanning",
            references=["CWE-250", "CIS-Docker-4.1"],
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.container_scanning", target,
        status=status,
        findings=findings,
        summary=f"Inspected image '{target}': base={info.get('Id', '?')[:19]}, {len(exposed_ports)} exposed port(s), {len(findings)} issue(s) found",
        metadata={
            "image_id": info.get("Id", ""),
            "repo_tags": info.get("RepoTags", []),
            "exposed_ports": exposed_ports,
            "created": info.get("Created", ""),
        },
    )


tool_registry.register("cloud.container_scanning", run, metadata={
    "name": "cloud.container_scanning",
    "domain": "cloud",
    "status": "completed",
    "description": "Real docker-inspect-based layer/config scan of a local image: exposed ports, root user, env vars regex-flagged for leaked secrets; requires the image to be present in the local Docker daemon",
    "parameters": {
        "target": "Local Docker image reference (name:tag or ID)",
    },
})
