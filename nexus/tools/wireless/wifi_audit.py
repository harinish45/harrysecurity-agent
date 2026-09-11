#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Wifi Audit
Domain: wireless

WiFi security auditing (scanning 802.11 traffic, enumerating access points and
clients, testing authentication) fundamentally requires a wireless adapter
capable of monitor mode, physically in RF range of the target network —
there's no network-observable substitute the way HTTP/TLS/DNS-based tools
have one. This previously ran `which <tool>` (a command that doesn't exist on
Windows and silently no-ops there) against a hardcoded, unrelated binary list
for every wireless tool regardless of its actual purpose, and always reported
status "completed" with a canned note — caught during this session's audit.
Now it checks for the aircrack-ng suite tools actually relevant to WiFi
auditing (airmon-ng/airodump-ng/iw) via `shutil.which`, and:
  - if none are present, honestly reports STATUS_REQUIRES_HARDWARE;
  - if one is present, does a real, read-only, non-disruptive enumeration of
    wireless interfaces on THIS host (never the remote `target`, which cannot
    be probed over 802.11 from software alone) — it never associates,
    injects, or fabricates capture data.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError

_RELEVANT_BINARIES = ("airmon-ng", "airodump-ng", "iw")


def run(target: str, **kwargs) -> dict:
    """wireless tool: Wifi Audit"""
    checked = {name: shutil.which(name) for name in _RELEVANT_BINARIES}
    available = {k: v for k, v in checked.items() if v}

    if not available:
        return tool_result(
            "wireless.wifi_audit", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"WiFi security auditing against {target} requires a wireless adapter "
                    f"capable of monitor mode plus the aircrack-ng suite (airmon-ng/"
                    f"airodump-ng) or `iw` — none of these are present on this host, so no "
                    f"802.11 traffic can be observed",
            error="requires_hardware: no airmon-ng, airodump-ng, or iw found on PATH",
            metadata={"checked_binaries": checked},
        )

    cmd = [available["airmon-ng"]] if "airmon-ng" in available else [available["iw"], "dev"]
    try:
        result = run_subprocess(cmd, timeout=10)
        output = result.stdout or ""
    except SandboxError as exc:
        return tool_result(
            "wireless.wifi_audit", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"WiFi audit tooling is installed but failed to enumerate wireless "
                    f"interfaces on this host: {exc}",
            error=str(exc),
            metadata={"checked_binaries": checked},
        )

    interfaces = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    if interfaces:
        findings.append(Finding(
            title="Wireless interface(s) detected on assessment host",
            severity="info", confidence="high", affected_asset=target,
            evidence="\n".join(interfaces[:20]),
            remediation="Confirm the adapter supports monitor mode before running an "
                        "authorized WiFi audit against the target network.",
            tool="wireless.wifi_audit",
        ))

    status = STATUS_COMPLETED if interfaces else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.wifi_audit", target,
        status=status,
        findings=findings,
        summary=f"WiFi audit tooling present ({', '.join(available)}); "
                f"{'found ' + str(len(interfaces)) + ' local wireless interface line(s)' if interfaces else 'no wireless interfaces enumerated'} "
                f"on this host. This lists LOCAL adapter capability only — it does not assess "
                f"{target} directly, which requires the operator to be RF-proximate to the "
                f"target network.",
        metadata={"checked_binaries": checked, "raw_output_sample": output[:500]},
    )


# Register with tool registry
tool_registry.register("wireless.wifi_audit", run, metadata={
    "name": "wireless.wifi_audit",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: WiFi security auditing — checks for a real aircrack-ng-suite "
                    "capable adapter (airmon-ng/airodump-ng/iw) on this host, enumerates local "
                    "wireless interfaces read-only if present, and honestly reports "
                    "requires_hardware if absent rather than fabricating a target assessment",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
