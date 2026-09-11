#!/usr/bin/env python3
"""
NEXUS-STRIKE — automation.bash_automation
Domain: automation
Real self-check of this platform's own bash automation capability: does a
`bash` interpreter genuinely exist on PATH, and does a real, safe,
read-only invocation (`bash -c "echo ..."`) actually succeed. This is a
self-check of NEXUS-STRIKE's execution environment, not an assessment of
`target` — running arbitrary shell playbooks *against* a remote target has
no network-observable substitute the way HTTP/DNS/TLS tools have one.

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

_PROBE_TOKEN = "nexus-strike-bash-check"


def run(target: str, **kwargs: Any) -> dict:
    """Self-check: is a real bash interpreter present and does it genuinely execute."""
    tool_name = "automation.bash_automation"
    node = platform.node()

    bash_path = shutil.which("bash")
    works = False
    if bash_path:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed, non-shell, read-only probe command
                [bash_path, "-c", f"echo {_PROBE_TOKEN}"],
                capture_output=True, text=True, timeout=5,
            )
            works = proc.returncode == 0 and _PROBE_TOKEN in proc.stdout
        except Exception:
            works = False

    if works:
        findings = [Finding(
            title="Bash automation runtime available",
            severity="info", confidence="certain",
            affected_asset=node,
            evidence=f"bash found at {bash_path!r}; a real 'bash -c echo {_PROBE_TOKEN}' round-trip succeeded.",
            remediation="No action needed — informational platform-capability check.",
            tool=tool_name,
        )]
    else:
        findings = [Finding(
            title="Bash automation runtime not available",
            severity="low", confidence="certain",
            affected_asset=node,
            evidence=f"shutil.which('bash') = {bash_path!r}",
            remediation="Install bash (or WSL/Git Bash on Windows) if bash-based automation playbooks are required.",
            tool=tool_name,
        )]

    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real local capability check: bash automation is "
                f"{'available' if works else 'not available'} on this platform ({node}). This is a "
                f"self-check of NEXUS-STRIKE's own execution environment, not an assessment of {target}.",
        metadata={"bash_path": bash_path, "confirmed_executable": works},
    )


tool_registry.register("automation.bash_automation", run, metadata={
    "name": "automation.bash_automation",
    "domain": "automation",
    "status": "completed",
    "description": "Real self-check of bash availability and executability on this platform",
    "parameters": {
        "target": "Unused for scanning purposes — this is a self-check of the local platform",
    },
})
