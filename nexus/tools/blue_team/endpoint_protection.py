#!/usr/bin/env python3
"""
NEXUS-STRIKE — blue_team tool: Endpoint Protection
Domain: blue_team

Whether `target` has its host-based protections (AV real-time protection,
host firewall, SELinux/AppArmor) actually enabled cannot be determined by
probing it over the network — those are local OS/security-suite settings
with no network-observable signal. This previously did a DNS resolve on
`target` and checked a handful of HTTP security response headers, calling
that "endpoint protection", unrelated to any endpoint control — caught
during this session's audit.

Now: this honestly reports STATUS_REQUIRES_CREDENTIALS for `target` (a
management-agent API or a remote/credentialed session on `target` is the
real way to check this), but — following the same "note" pattern
`hardware.usb_attacks` and `blue_team.edr_analysis` use — it runs a real
protection-status check against the LOCAL analysis host: on Windows,
`Get-MpComputerStatus` (Defender real-time protection) and `netsh
advfirewall show currentprofile state` (host firewall); on Linux,
`getenforce`/`aa-status`/`systemctl is-active auditd`. That result is
explicitly labeled as describing the analysis host, never `target`.
"""
import json
import platform
import subprocess

from nexus.foundation.schema import STATUS_REQUIRES_CREDENTIALS, tool_result
from nexus.tools.registry import tool_registry


def _check_windows_defender():
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-MpComputerStatus | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        data = json.loads(proc.stdout)
        return {
            "AntivirusEnabled": data.get("AntivirusEnabled"),
            "RealTimeProtectionEnabled": data.get("RealTimeProtectionEnabled"),
            "AntispywareEnabled": data.get("AntispywareEnabled"),
            "NISEnabled": data.get("NISEnabled"),
        }
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _check_windows_firewall():
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile", "state"],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout.strip()[:500]
    except (OSError, subprocess.SubprocessError):
        return None


def _check_linux_protection():
    checks = {}
    for name, cmd in (
        ("selinux_getenforce", ["getenforce"]),
        ("apparmor_status", ["aa-status", "--enabled"]),
        ("auditd_active", ["systemctl", "is-active", "auditd"]),
        ("ufw_status", ["ufw", "status"]),
    ):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            checks[name] = (proc.stdout.strip() or proc.stderr.strip())[:200]
        except (OSError, subprocess.SubprocessError):
            checks[name] = "not available on this host"
    return checks


def run(target: str, **kwargs) -> dict:
    """blue_team tool: Endpoint Protection"""
    local_node = platform.node()
    system = platform.system()

    local_status: dict = {}
    if system == "Windows":
        method = "Get-MpComputerStatus + netsh advfirewall (local host)"
        defender = _check_windows_defender()
        firewall = _check_windows_firewall()
        if defender is not None:
            local_status["windows_defender"] = defender
        if firewall is not None:
            local_status["windows_firewall_state"] = firewall
    else:
        method = "getenforce / aa-status / systemctl / ufw (local host, best-effort)"
        local_status = _check_linux_protection()

    return tool_result(
        "blue_team.endpoint_protection", target,
        status=STATUS_REQUIRES_CREDENTIALS,
        summary=f"Checking {target}'s host-based protection state (AV real-time protection, "
                f"host firewall, SELinux/AppArmor) requires a management-agent API or a "
                f"credentialed/remote session on {target} — none of that is observable over "
                f"the network",
        error=f"requires_credentials: no management-agent API or remote-session access to {target}",
        metadata={
            "note": f"The protection-status data below describes the machine nexus-strike "
                    f"itself is running on ({local_node}), NOT {target} — it is diagnostic "
                    f"context only, not a target assessment.",
            "local_node": local_node,
            "local_platform": platform.platform(),
            "detection_method": method,
            "local_endpoint_protection_status": local_status,
        },
    )


# Register with tool registry
tool_registry.register("blue_team.endpoint_protection", run, metadata={
    "name": "blue_team.endpoint_protection",
    "domain": "blue_team",
    "status": "requires_credentials",
    "description": "blue_team tool: honestly reports that target-side endpoint protection "
                    "state requires credentialed access to the target; diagnostically checks "
                    "the LOCAL analysis host's own AV/firewall/MAC status",
    "parameters": {
        "target": "Target domain, IP, or URL (not queried directly — see description)",
    },
})
