#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Evil Twin
Domain: wireless

Evil-twin testing (standing up a rogue AP that impersonates a target SSID to
lure clients) requires a wireless adapter capable of AP/master mode plus
hostapd, physically in RF range of the target's clients — no network-
observable substitute exists. This previously ran `which <tool>` (a no-op on
Windows) against a hardcoded, unrelated binary list and always reported
status "completed" with a canned note — caught during this session's audit.
Now it checks for the actual evil-twin-relevant tools (hostapd/airmon-ng) via
`shutil.which`, and:
  - if absent, honestly reports STATUS_REQUIRES_HARDWARE;
  - if present, does a real, read-only, non-disruptive enumeration of
    wireless interfaces on THIS host — it deliberately never actually starts
    a rogue AP (that would be an active, potentially disruptive attack and
    must never fire from a prerequisite check) and never fabricates lured
    client data.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError

_RELEVANT_BINARIES = ("hostapd", "airmon-ng")


def run(target: str, **kwargs) -> dict:
    """wireless tool: Evil Twin"""
    checked = {name: shutil.which(name) for name in _RELEVANT_BINARIES}
    available = {k: v for k, v in checked.items() if v}

    if not available:
        return tool_result(
            "wireless.evil_twin", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Evil-twin testing against {target} requires a wireless adapter capable "
                    f"of AP/master mode plus hostapd — none of these are present on this host, "
                    f"so no rogue AP impersonating the target SSID can be started",
            error="requires_hardware: no hostapd or airmon-ng found on PATH",
            metadata={"checked_binaries": checked},
        )

    cmd = [available["airmon-ng"]] if "airmon-ng" in available else [available["hostapd"], "-v"]
    try:
        result = run_subprocess(cmd, timeout=10)
        output = result.stdout or ""
    except SandboxError as exc:
        return tool_result(
            "wireless.evil_twin", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Evil-twin tooling is installed but failed to enumerate wireless "
                    f"interfaces on this host: {exc}",
            error=str(exc),
            metadata={"checked_binaries": checked},
        )

    interfaces = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    if interfaces:
        findings.append(Finding(
            title="Wireless interface(s) detected — evil-twin-capable tooling present",
            severity="info", confidence="high", affected_asset=target,
            evidence="\n".join(interfaces[:20]),
            remediation="An authorized evil-twin test still requires explicit operator action "
                        "and a scoped hostapd configuration — this tool intentionally does not "
                        "start a rogue AP automatically.",
            tool="wireless.evil_twin",
        ))

    status = STATUS_COMPLETED if interfaces else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.evil_twin", target,
        status=status,
        findings=findings,
        summary=f"Evil-twin-capable tooling present ({', '.join(available)}); "
                f"{'found ' + str(len(interfaces)) + ' local wireless interface line(s)' if interfaces else 'no wireless interfaces enumerated'} "
                f"on this host. No rogue AP was started — this only confirms local capability, "
                f"it does not assess {target} directly.",
        metadata={"checked_binaries": checked, "raw_output_sample": output[:500]},
    )


# Register with tool registry
tool_registry.register("wireless.evil_twin", run, metadata={
    "name": "wireless.evil_twin",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: evil-twin AP testing — checks for a real AP-capable adapter "
                    "plus hostapd on this host, enumerates local wireless interfaces read-only "
                    "if present (never starts a live rogue AP automatically), and honestly "
                    "reports requires_hardware if absent",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
