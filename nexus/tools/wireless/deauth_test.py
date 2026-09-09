#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Deauth Test
Domain: wireless

Deauthentication testing (sending 802.11 deauth/disassoc frames to probe a
target's resilience) requires a wireless adapter capable of both monitor mode
and packet injection, in RF range of the target network — no network-
observable substitute exists. This previously ran `which <tool>` (a no-op on
Windows) against a hardcoded, unrelated binary list and always reported
status "completed" with a canned note — caught during this session's audit.
Now it checks for the actual deauth-relevant aircrack-ng tools
(aireplay-ng/airmon-ng) via `shutil.which`, and:
  - if absent, honestly reports STATUS_REQUIRES_HARDWARE;
  - if present, does a real, read-only, non-disruptive enumeration of
    wireless interfaces on THIS host — it deliberately never actually sends
    a deauth frame (that would be an active attack against a live network
    and must never fire from a prerequisite check) and never fabricates
    client/AP data.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError

_RELEVANT_BINARIES = ("aireplay-ng", "airmon-ng")


def run(target: str, **kwargs) -> dict:
    """wireless tool: Deauth Test"""
    checked = {name: shutil.which(name) for name in _RELEVANT_BINARIES}
    available = {k: v for k, v in checked.items() if v}

    if not available:
        return tool_result(
            "wireless.deauth_test", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Deauthentication testing against {target} requires a wireless adapter "
                    f"capable of monitor mode and packet injection plus aireplay-ng/airmon-ng "
                    f"— none of these are present on this host, so no deauth frames can be sent",
            error="requires_hardware: no aireplay-ng or airmon-ng found on PATH",
            metadata={"checked_binaries": checked},
        )

    cmd = [available["airmon-ng"]] if "airmon-ng" in available else [available["aireplay-ng"], "--help"]
    try:
        result = run_subprocess(cmd, timeout=10)
        output = result.stdout or ""
    except SandboxError as exc:
        return tool_result(
            "wireless.deauth_test", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Deauth tooling is installed but failed to enumerate wireless interfaces "
                    f"on this host: {exc}",
            error=str(exc),
            metadata={"checked_binaries": checked},
        )

    interfaces = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    if interfaces:
        findings.append(Finding(
            title="Wireless interface(s) detected — deauth-capable tooling present",
            severity="info", confidence="high", affected_asset=target,
            evidence="\n".join(interfaces[:20]),
            remediation="An authorized, scoped deauth test still requires explicit operator "
                        "action against a confirmed in-scope AP/client — this tool intentionally "
                        "does not send deauth frames automatically.",
            tool="wireless.deauth_test",
        ))

    status = STATUS_COMPLETED if interfaces else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.deauth_test", target,
        status=status,
        findings=findings,
        summary=f"Deauth-capable tooling present ({', '.join(available)}); "
                f"{'found ' + str(len(interfaces)) + ' local wireless interface line(s)' if interfaces else 'no wireless interfaces enumerated'} "
                f"on this host. No deauth frames were sent — this only confirms local capability, "
                f"it does not assess {target} directly.",
        metadata={"checked_binaries": checked, "raw_output_sample": output[:500]},
    )


# Register with tool registry
tool_registry.register("wireless.deauth_test", run, metadata={
    "name": "wireless.deauth_test",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: 802.11 deauthentication testing — checks for a real "
                    "injection-capable adapter (aireplay-ng/airmon-ng) on this host, enumerates "
                    "local wireless interfaces read-only if present (never sends live deauth "
                    "frames automatically), and honestly reports requires_hardware if absent",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
