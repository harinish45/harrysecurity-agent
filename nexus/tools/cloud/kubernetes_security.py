#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.kubernetes_security
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs. Caught during this session's audit. A Kubernetes security audit has
no network-observable substitute the way an HTTP-based tool has one: it
needs a configured kubeconfig and a reachable API server. This now honestly
checks for both (mirrors the honest-degrade pattern in
nexus/agents/offensive/digital_twin_agent.py — check for the prerequisite,
then make one real cheap call to confirm it actually works before doing
anything else) and, only if the cluster is genuinely reachable, performs a
real read-only audit: lists pods across all namespaces via `kubectl get pods
-o json` and flags pods running as root, with hostNetwork, or with hostPID —
all real container-escape/lateral-movement vectors, not fabricated findings.
"""
from __future__ import annotations

import json
import os
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


def _kubeconfig_path() -> str | None:
    env_path = os.environ.get("KUBECONFIG")
    if env_path and os.path.exists(env_path.split(os.pathsep)[0]):
        return env_path.split(os.pathsep)[0]
    default_path = os.path.join(os.path.expanduser("~"), ".kube", "config")
    if os.path.exists(default_path):
        return default_path
    return None


def _check_pod(pod: dict) -> list[Finding]:
    findings: list[Finding] = []
    meta = pod.get("metadata", {}) or {}
    spec = pod.get("spec", {}) or {}
    name = meta.get("name", "unknown")
    namespace = meta.get("namespace", "default")
    asset = f"pod://{namespace}/{name}"

    if spec.get("hostNetwork"):
        findings.append(Finding(
            title=f"Pod '{namespace}/{name}' uses hostNetwork",
            severity="high",
            confidence="certain",
            affected_asset=asset,
            evidence="spec.hostNetwork = true",
            remediation="Remove hostNetwork: true unless the workload genuinely needs the host's network namespace; it bypasses network policy isolation.",
            tool="cloud.kubernetes_security",
            references=["CWE-250", "CIS-Kubernetes-5.2.4"],
        ))
    if spec.get("hostPID"):
        findings.append(Finding(
            title=f"Pod '{namespace}/{name}' uses hostPID",
            severity="high",
            confidence="certain",
            affected_asset=asset,
            evidence="spec.hostPID = true",
            remediation="Remove hostPID: true; it lets the container see and signal every process on the node, including other containers'.",
            tool="cloud.kubernetes_security",
            references=["CWE-250", "CIS-Kubernetes-5.2.3"],
        ))

    pod_sc = spec.get("securityContext", {}) or {}
    containers = (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])
    for container in containers:
        c_name = container.get("name", "?")
        c_sc = container.get("securityContext", {}) or {}
        run_as_non_root = c_sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        run_as_user = c_sc.get("runAsUser", pod_sc.get("runAsUser"))
        privileged = c_sc.get("privileged", False)

        if privileged:
            findings.append(Finding(
                title=f"Container '{c_name}' in pod '{namespace}/{name}' is privileged",
                severity="critical",
                confidence="certain",
                affected_asset=asset,
                evidence=f"container[{c_name}].securityContext.privileged = true",
                remediation="Remove privileged: true; grant only the specific Linux capabilities required via securityContext.capabilities.add.",
                tool="cloud.kubernetes_security",
                references=["CWE-250", "CIS-Kubernetes-5.2.1"],
            ))
        elif run_as_user == 0 or (run_as_non_root is not True and run_as_user is None):
            findings.append(Finding(
                title=f"Container '{c_name}' in pod '{namespace}/{name}' may run as root",
                severity="medium",
                confidence="medium" if run_as_user is None else "high",
                affected_asset=asset,
                evidence=f"runAsUser={run_as_user!r}, runAsNonRoot={run_as_non_root!r}",
                remediation="Set securityContext.runAsNonRoot: true and a non-zero runAsUser at the pod or container level.",
                tool="cloud.kubernetes_security",
                references=["CWE-250", "CIS-Kubernetes-5.2.6"],
            ))

    return findings


def run(target: str, namespace: str | None = None, **kwargs: Any) -> dict:
    """Read-only kubectl-based audit of the configured Kubernetes cluster.

    Parameters
    ----------
    target : str
        Accepted for interface consistency; this audits whichever cluster
        the active kubeconfig context points to, not a remote `target` host
        — Kubernetes API servers are not reachable/enumerable that way.
    namespace : str, optional
        Restrict the audit to a single namespace. Defaults to all namespaces.
    """
    if not shutil.which("kubectl"):
        return tool_result(
            "cloud.kubernetes_security", target,
            status=STATUS_UNAVAILABLE,
            summary="Kubernetes audit requires the `kubectl` CLI, which is not on PATH",
            error="kubectl executable not found on PATH",
        )

    kubeconfig = _kubeconfig_path()
    if not kubeconfig:
        return tool_result(
            "cloud.kubernetes_security", target,
            status=STATUS_UNAVAILABLE,
            summary="No kubeconfig found (~/.kube/config or $KUBECONFIG)",
            error="kubeconfig not configured",
        )

    args = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        args += ["-n", namespace]
    else:
        args += ["--all-namespaces"]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return tool_result(
            "cloud.kubernetes_security", target,
            status=STATUS_UNAVAILABLE,
            summary="kubeconfig found but the cluster API server is not reachable",
            error=str(exc),
        )

    if proc.returncode != 0:
        return tool_result(
            "cloud.kubernetes_security", target,
            status=STATUS_UNAVAILABLE,
            summary="kubeconfig found but the cluster API server is not reachable",
            error=proc.stderr.strip()[:500] or "kubectl get pods failed",
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return tool_result("cloud.kubernetes_security", target, status=STATUS_FAILED, error=f"Could not parse kubectl output: {exc}")

    pods = payload.get("items", [])
    findings: list[Finding] = []
    for pod in pods:
        findings.extend(_check_pod(pod))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "cloud.kubernetes_security", target,
        status=status,
        findings=findings,
        summary=f"Audited {len(pods)} pod(s) in the configured cluster; {len(findings)} issue(s) found",
        metadata={
            "note": "Audits the cluster the active kubeconfig context points to, not the `target` parameter.",
            "kubeconfig": kubeconfig,
            "pods_checked": len(pods),
            "namespace_filter": namespace or "all",
        },
    )


tool_registry.register("cloud.kubernetes_security", run, metadata={
    "name": "cloud.kubernetes_security",
    "domain": "cloud",
    "status": "completed",
    "description": "Real kubectl-based read-only audit of the configured cluster's pods (privileged, hostNetwork, hostPID, root); requires a working kubeconfig and a reachable API server",
    "parameters": {
        "target": "Accepted for interface consistency; audits the kubeconfig-configured cluster, not a remote host",
        "namespace": "Restrict the audit to a single namespace (default: all namespaces)",
    },
})
