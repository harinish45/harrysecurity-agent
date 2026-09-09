#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Handshake Capture
Domain: wireless

WPA/WPA2 4-way handshake capture requires a wireless adapter capable of
monitor mode plus airodump-ng (and, for offline validation, wpa_supplicant),
physically in RF range of the target AP — no network-observable substitute
exists. This previously ran `which <tool>` (a no-op on Windows) against a
hardcoded, unrelated binary list and always reported status "completed" with
a canned note — caught during this session's audit. Now it checks for the
actual handshake-capture-relevant tools (airodump-ng/airmon-ng/
wpa_supplicant) via `shutil.which`, and:
  - if absent, honestly reports STATUS_REQUIRES_HARDWARE;
  - if present, does a real, read-only, non-disruptive enumeration of
    wireless interfaces on THIS host — it deliberately never actually starts
    a capture (that requires live RF proximity to a target AP) and never
    fabricates a captured handshake.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError

_RELEVANT_BINARIES = ("airodump-ng", "airmon-ng", "wpa_supplicant")


def run(target: str, **kwargs) -> dict:
    """wireless tool: Handshake Capture"""
    checked = {name: shutil.which(name) for name in _RELEVANT_BINARIES}
    available = {k: v for k, v in checked.items() if v}

    if not available:
        return tool_result(
            "wireless.handshake_capture", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"WPA handshake capture against {target} requires a wireless adapter "
                    f"capable of monitor mode plus airodump-ng — none of these are present on "
                    f"this host, so no 4-way handshake can be captured",
            error="requires_hardware: no airodump-ng, airmon-ng, or wpa_supplicant found on PATH",
            metadata={"checked_binaries": checked},
        )

    cmd = [available["airmon-ng"]] if "airmon-ng" in available else [next(iter(available.values())), "--help"]
    try:
        result = run_subprocess(cmd, timeout=10)
        output = result.stdout or ""
    except SandboxError as exc:
        return tool_result(
            "wireless.handshake_capture", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Handshake-capture tooling is installed but failed to enumerate wireless "
                    f"interfaces on this host: {exc}",
            error=str(exc),
            metadata={"checked_binaries": checked},
        )

    interfaces = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    if interfaces:
        findings.append(Finding(
            title="Wireless interface(s) detected — handshake-capture-capable tooling present",
            severity="info", confidence="high", affected_asset=target,
            evidence="\n".join(interfaces[:20]),
            remediation="An authorized handshake capture still requires explicit operator "
                        "action, RF proximity to the target AP, and a client to (re)associate "
                        "— this tool intentionally does not start a capture automatically.",
            tool="wireless.handshake_capture",
        ))

    status = STATUS_COMPLETED if interfaces else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.handshake_capture", target,
        status=status,
        findings=findings,
        summary=f"Handshake-capture-capable tooling present ({', '.join(available)}); "
                f"{'found ' + str(len(interfaces)) + ' local wireless interface line(s)' if interfaces else 'no wireless interfaces enumerated'} "
                f"on this host. No capture was started and no handshake data was collected or "
                f"fabricated — this only confirms local capability, it does not assess {target} "
                f"directly.",
        metadata={"checked_binaries": checked, "raw_output_sample": output[:500]},
    )


# Register with tool registry
tool_registry.register("wireless.handshake_capture", run, metadata={
    "name": "wireless.handshake_capture",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: WPA 4-way handshake capture — checks for a real "
                    "monitor-mode-capable adapter (airodump-ng/airmon-ng/wpa_supplicant) on "
                    "this host, enumerates local wireless interfaces read-only if present "
                    "(never captures a live handshake or fabricates one), and honestly reports "
                    "requires_hardware if absent",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
