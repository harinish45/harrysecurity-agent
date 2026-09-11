#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.docker_security
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud" stubs,
none of which had anything to do with Docker. Caught during this session's
audit. Docker container security auditing has no network-observable
substitute: it requires a local Docker daemon to query. This now honestly
checks for that daemon (mirrors the honest-degrade pattern in
nexus/agents/offensive/digital_twin_agent.py: `shutil.which("docker")` then a
real `docker` CLI call, STATUS_UNAVAILABLE if either step fails) and, when a
daemon *is* reachable, performs a real read-only audit of running containers:
flags `--privileged` containers, Docker-socket bind mounts (a well-known
container-escape vector), and container ports published to 0.0.0.0.

`target` is accepted for interface consistency with every other tool, but
this audits whatever Docker daemon is reachable from the machine running
nexus-strike — not a remote `target` host, which Docker's remote API is not
exposed to reach by default. That distinction is called out in the summary,
the same way usb_attacks.py/digital_twin_agent.py flag "this describes the
local machine, not the target".
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


def _docker_json(args: list[str], timeout: int = _TIMEOUT):
    """Run a docker CLI subcommand and parse JSON(-lines) output."""
    proc = subprocess.run(
        ["docker"] + args,
        capture_output=True, text=True, timeout=timeout, check=True,
    )
    return proc.stdout


def _check_container(inspect: dict) -> list[Finding]:
    findings: list[Finding] = []
    name = inspect.get("Name", "").lstrip("/") or inspect.get("Id", "unknown")[:12]
    host_config = inspect.get("HostConfig", {}) or {}

    if host_config.get("Privileged"):
        findings.append(Finding(
            title=f"Container '{name}' running with --privileged",
            severity="critical",
            confidence="certain",
            affected_asset=f"docker://{name}",
            evidence="HostConfig.Privileged = true",
            remediation="Remove --privileged; grant only the specific Linux capabilities the container needs via --cap-add.",
            tool="cloud.docker_security",
            references=["CWE-250", "CIS-Docker-5.4"],
        ))

    for mount in inspect.get("Mounts", []) or []:
        source = str(mount.get("Source", ""))
        if "docker.sock" in source:
            findings.append(Finding(
                title=f"Container '{name}' has the Docker socket mounted",
                severity="critical",
                confidence="certain",
                affected_asset=f"docker://{name}",
                evidence=f"Bind mount source: {source}",
                remediation="Do not mount /var/run/docker.sock into containers; it grants root-equivalent control of the host. Use a proxy with scoped access if container orchestration from within a container is required.",
                tool="cloud.docker_security",
                references=["CWE-250", "CIS-Docker-5.31"],
            ))

    ports = (inspect.get("NetworkSettings", {}) or {}).get("Ports", {}) or {}
    for container_port, bindings in ports.items():
        for binding in bindings or []:
            host_ip = binding.get("HostIp", "")
            if host_ip in ("0.0.0.0", "::", ""):
                findings.append(Finding(
                    title=f"Container '{name}' publishes {container_port} to all interfaces",
                    severity="medium",
                    confidence="high",
                    affected_asset=f"docker://{name}",
                    evidence=f"{container_port} -> {host_ip or '0.0.0.0'}:{binding.get('HostPort', '?')}",
                    remediation="Bind published ports to 127.0.0.1 or an internal interface unless the service must be reachable externally.",
                    tool="cloud.docker_security",
                    references=["CWE-284", "CIS-Docker-5.9"],
                ))

    return findings


def run(target: str, **kwargs: Any) -> dict:
    """Read-only audit of the local Docker daemon's running containers.

    Parameters
    ----------
    target : str
        Accepted for interface consistency; this audits the local Docker
        daemon reachable from the nexus-strike host, not a remote `target`.
    """
    if not shutil.which("docker"):
        return tool_result(
            "cloud.docker_security", target,
            status=STATUS_UNAVAILABLE,
            summary="Docker container audit requires the `docker` CLI, which is not on PATH",
            error="docker executable not found on PATH",
        )

    try:
        subprocess.run(
            ["docker", "info", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=_TIMEOUT, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        return tool_result(
            "cloud.docker_security", target,
            status=STATUS_UNAVAILABLE,
            summary="Docker CLI found but the daemon is not reachable",
            error=f"`docker info` failed: {exc}",
        )

    try:
        ids_output = _docker_json(["ps", "-q"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        return tool_result(
            "cloud.docker_security", target,
            status=STATUS_FAILED,
            error=f"`docker ps` failed: {exc}",
        )

    container_ids = [c for c in ids_output.splitlines() if c.strip()]
    if not container_ids:
        return tool_result(
            "cloud.docker_security", target,
            status=STATUS_NO_FINDINGS,
            summary="Docker daemon reachable; no running containers to audit",
            metadata={"note": "Audits the local Docker daemon, not the `target` parameter.", "containers_checked": 0},
        )

    findings: list[Finding] = []
    containers_checked = 0
    for cid in container_ids:
        try:
            raw = _docker_json(["inspect", cid])
            inspected = json.loads(raw)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            continue
        for entry in inspected:
            findings.extend(_check_container(entry))
            containers_checked += 1

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.docker_security", target,
        status=status,
        findings=findings,
        summary=f"Audited {containers_checked} running container(s) on the local Docker daemon; {len(findings)} issue(s) found",
        metadata={"note": "Audits the local Docker daemon, not the `target` parameter.", "containers_checked": containers_checked},
    )


tool_registry.register("cloud.docker_security", run, metadata={
    "name": "cloud.docker_security",
    "domain": "cloud",
    "status": "completed",
    "description": "Read-only audit of the local Docker daemon's running containers (privileged mode, docker.sock mounts, 0.0.0.0-exposed ports); requires a reachable local Docker daemon",
    "parameters": {
        "target": "Accepted for interface consistency; audits the local Docker daemon, not a remote host",
    },
})
