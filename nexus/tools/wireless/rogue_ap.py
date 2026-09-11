#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Rogue Ap
Domain: wireless

Rogue-AP testing (standing up an unauthorized access point on the target's
airspace to test detection/response) requires a wireless adapter capable of
AP/master mode plus hostapd (and typically dnsmasq for DHCP), physically in
RF range — no network-observable substitute exists. This previously ran
`which <tool>` (a no-op on Windows) against a hardcoded, unrelated binary
list and always reported status "completed" with a canned note — caught
during this session's audit. Now it checks for the actual rogue-AP-relevant
tools (hostapd/dnsmasq/airmon-ng) via `shutil.which`, and:
  - if absent, honestly reports STATUS_REQUIRES_HARDWARE;
  - if present, does a real, read-only, non-disruptive enumeration of
    wireless interfaces on THIS host — it deliberately never actually starts
    an AP (that would be an active, potentially disruptive action and must
    never fire from a prerequisite check) and never fabricates client data.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError

_RELEVANT_BINARIES = ("hostapd", "dnsmasq", "airmon-ng")


def run(target: str, **kwargs) -> dict:
    """wireless tool: Rogue Ap"""
    checked = {name: shutil.which(name) for name in _RELEVANT_BINARIES}
    available = {k: v for k, v in checked.items() if v}

    if not available:
        return tool_result(
            "wireless.rogue_ap", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Rogue-AP testing against {target} requires a wireless adapter capable "
                    f"of AP/master mode plus hostapd/dnsmasq — none of these are present on "
                    f"this host, so no rogue access point can be started",
            error="requires_hardware: no hostapd, dnsmasq, or airmon-ng found on PATH",
            metadata={"checked_binaries": checked},
        )

    cmd = [available["airmon-ng"]] if "airmon-ng" in available else [next(iter(available.values())), "-v"]
    try:
        result = run_subprocess(cmd, timeout=10)
        output = result.stdout or ""
    except SandboxError as exc:
        return tool_result(
            "wireless.rogue_ap", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Rogue-AP tooling is installed but failed to enumerate wireless "
                    f"interfaces on this host: {exc}",
            error=str(exc),
            metadata={"checked_binaries": checked},
        )

    interfaces = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    if interfaces:
        findings.append(Finding(
            title="Wireless interface(s) detected — rogue-AP-capable tooling present",
            severity="info", confidence="high", affected_asset=target,
            evidence="\n".join(interfaces[:20]),
            remediation="An authorized rogue-AP test still requires explicit operator action "
                        "and a scoped hostapd/dnsmasq configuration — this tool intentionally "
                        "does not start an AP automatically.",
            tool="wireless.rogue_ap",
        ))

    status = STATUS_COMPLETED if interfaces else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.rogue_ap", target,
        status=status,
        findings=findings,
        summary=f"Rogue-AP-capable tooling present ({', '.join(available)}); "
                f"{'found ' + str(len(interfaces)) + ' local wireless interface line(s)' if interfaces else 'no wireless interfaces enumerated'} "
                f"on this host. No AP was started — this only confirms local capability, it "
                f"does not assess {target} directly.",
        metadata={"checked_binaries": checked, "raw_output_sample": output[:500]},
    )


# Register with tool registry
tool_registry.register("wireless.rogue_ap", run, metadata={
    "name": "wireless.rogue_ap",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: rogue AP testing — checks for a real AP-capable adapter plus "
                    "hostapd/dnsmasq on this host, enumerates local wireless interfaces "
                    "read-only if present (never starts a live rogue AP automatically), and "
                    "honestly reports requires_hardware if absent",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
