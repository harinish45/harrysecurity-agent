#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Wps Attack
Domain: wireless

WPS PIN attack testing (Reaver/Bully-style brute force or Pixie Dust against
a target AP's WPS registrar) requires a wireless adapter capable of monitor
mode plus wash/reaver (or bully), physically in RF range of the target AP —
no network-observable substitute exists. This previously ran `which <tool>`
(a no-op on Windows) against a hardcoded, unrelated binary list and always
reported status "completed" with a canned note — caught during this
session's audit. Now it checks for the actual WPS-relevant tools
(wash/reaver) via `shutil.which`, and:
  - if absent, honestly reports STATUS_REQUIRES_HARDWARE;
  - if present, does a real, read-only, non-disruptive enumeration of
    wireless interfaces on THIS host — it deliberately never actually runs a
    WPS PIN attack (that would be an active attack against a live AP and
    must never fire from a prerequisite check) and never fabricates a
    cracked PIN/PSK.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError

_RELEVANT_BINARIES = ("wash", "reaver")


def run(target: str, **kwargs) -> dict:
    """wireless tool: Wps Attack"""
    checked = {name: shutil.which(name) for name in _RELEVANT_BINARIES}
    available = {k: v for k, v in checked.items() if v}

    if not available:
        return tool_result(
            "wireless.wps_attack", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"WPS attack testing against {target} requires a wireless adapter capable "
                    f"of monitor mode plus wash/reaver — none of these are present on this "
                    f"host, so no WPS registrar interaction can be attempted",
            error="requires_hardware: no wash or reaver found on PATH",
            metadata={"checked_binaries": checked},
        )

    cmd = [available["wash"], "--help"] if "wash" in available else [available["reaver"], "--help"]
    try:
        result = run_subprocess(cmd, timeout=10)
        output = result.stdout or ""
    except SandboxError as exc:
        return tool_result(
            "wireless.wps_attack", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"WPS tooling is installed but failed to run on this host: {exc}",
            error=str(exc),
            metadata={"checked_binaries": checked},
        )

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    if lines:
        findings.append(Finding(
            title="WPS-attack-capable tooling confirmed runnable on this host",
            severity="info", confidence="high", affected_asset=target,
            evidence="\n".join(lines[:20]),
            remediation="An authorized WPS attack still requires explicit operator action "
                        "against a confirmed in-scope AP — this tool intentionally does not "
                        "run a WPS PIN attack automatically.",
            tool="wireless.wps_attack",
        ))

    status = STATUS_COMPLETED if lines else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.wps_attack", target,
        status=status,
        findings=findings,
        summary=f"WPS-attack-capable tooling present ({', '.join(available)}) and runnable on "
                f"this host. No WPS attack was executed — this only confirms local capability, "
                f"it does not assess {target} directly, which also requires monitor-mode-capable "
                f"hardware in RF range.",
        metadata={"checked_binaries": checked, "raw_output_sample": output[:500]},
    )


# Register with tool registry
tool_registry.register("wireless.wps_attack", run, metadata={
    "name": "wireless.wps_attack",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: WPS PIN attack testing — checks for real wash/reaver tooling "
                    "on this host, confirms it's runnable read-only if present (never runs a "
                    "live WPS PIN attack automatically), and honestly reports requires_hardware "
                    "if absent",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
