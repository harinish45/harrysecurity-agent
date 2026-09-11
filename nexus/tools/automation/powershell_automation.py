#!/usr/bin/env python3
"""
NEXUS-STRIKE — automation.powershell_automation
Domain: automation
Real self-check of this platform's own PowerShell automation capability:
does `powershell` or `pwsh` genuinely exist on PATH, and does a real, safe,
read-only invocation (`-Command "Write-Output ..."`) actually succeed. This
is a self-check of NEXUS-STRIKE's execution environment, not an assessment
of `target` — running arbitrary PowerShell playbooks *against* a remote
target has no network-observable substitute the way HTTP/DNS/TLS tools have
one.

Previously this ignored `target` entirely (beyond a bare DNS resolve + HTTP
GET on "/", byte-for-byte identical to 19 other stub tools; a still-earlier
version unsafely read `target` as a local file path) — caught during this
session's audit.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Any

from nexus.foundation.schema import Finding, STATUS_COMPLETED, tool_result
from nexus.tools.registry import tool_registry

_PROBE_TOKEN = "nexus-strike-powershell-check"


def run(target: str, **kwargs: Any) -> dict:
    """Self-check: is a real PowerShell interpreter present and does it genuinely execute."""
    tool_name = "automation.powershell_automation"
    node = platform.node()

    ps_path = shutil.which("pwsh") or shutil.which("powershell")
    works = False
    if ps_path:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed, non-shell, read-only probe command
                [ps_path, "-NoProfile", "-NonInteractive", "-Command", f"Write-Output {_PROBE_TOKEN}"],
                capture_output=True, text=True, timeout=10,
            )
            works = proc.returncode == 0 and _PROBE_TOKEN in proc.stdout
        except Exception:
            works = False

    if works:
        findings = [Finding(
            title="PowerShell automation runtime available",
            severity="info", confidence="certain",
            affected_asset=node,
            evidence=f"PowerShell found at {ps_path!r}; a real 'Write-Output {_PROBE_TOKEN}' round-trip succeeded.",
            remediation="No action needed — informational platform-capability check.",
            tool=tool_name,
        )]
    else:
        findings = [Finding(
            title="PowerShell automation runtime not available",
            severity="low", confidence="certain",
            affected_asset=node,
            evidence=f"shutil.which('pwsh'/'powershell') = {ps_path!r}",
            remediation="Install PowerShell (pwsh) if PowerShell-based automation playbooks are required.",
            tool=tool_name,
        )]

    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real local capability check: PowerShell automation is "
                f"{'available' if works else 'not available'} on this platform ({node}). This is a "
                f"self-check of NEXUS-STRIKE's own execution environment, not an assessment of {target}.",
        metadata={"powershell_path": ps_path, "confirmed_executable": works},
    )


tool_registry.register("automation.powershell_automation", run, metadata={
    "name": "automation.powershell_automation",
    "domain": "automation",
    "status": "completed",
    "description": "Real self-check of PowerShell (pwsh/powershell) availability and executability on this platform",
    "parameters": {
        "target": "Unused for scanning purposes — this is a self-check of the local platform",
    },
})
