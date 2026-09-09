#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Secure Boot Testing
Domain: hardware

Secure Boot state fundamentally lives in the target's own firmware (UEFI
NVRAM) — there's no network-observable substitute. This previously
reported generic `platform.platform()` / `lsusb` output as if it were a
Secure Boot assessment, always with status "completed" — caught during
this session's audit (byte-for-byte identical to fault_injection.py,
nfc_testing.py, etc.).

Now it performs a REAL, read-only Secure Boot state query against whatever
machine nexus-strike itself is running on (Linux: `mokutil --sb-state`;
Windows: `Confirm-SecureBootUEFI` via PowerShell) and reports that
honestly as local diagnostic context — never as an assessment of
`target`, since assessing a *remote* target's Secure Boot state requires
either physical/firmware access or an authenticated agent running on that
target, neither of which this tool has.
"""
from __future__ import annotations

import platform
import shutil

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import SandboxError, run_subprocess


def _linux_secure_boot_probe() -> dict:
    info: dict = {"checked": False}
    mokutil = shutil.which("mokutil")
    if not mokutil:
        info["note"] = "mokutil not installed — cannot query Secure Boot state on this machine"
        return info
    try:
        result = run_subprocess([mokutil, "--sb-state"], timeout=10)
        output = (result.stdout or "").strip()
        info["checked"] = True
        info["mokutil_output"] = output[:500]
        info["secure_boot_enabled"] = "SecureBoot enabled" in output
    except (SandboxError, FileNotFoundError, OSError) as e:
        info["error"] = f"mokutil invocation failed: {e}"
    return info


def _windows_secure_boot_probe() -> dict:
    info: dict = {"checked": False}
    try:
        result = run_subprocess(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Confirm-SecureBootUEFI"],
            timeout=15,
        )
        output = (result.stdout or "").strip()
        info["checked"] = True
        info["confirm_secure_boot_output"] = output[:500]
        info["secure_boot_enabled"] = output.strip().lower() == "true"
    except (SandboxError, FileNotFoundError, OSError) as e:
        # Confirm-SecureBootUEFI throws on legacy BIOS machines (not UEFI) —
        # that's still a real, honest answer ("not UEFI"), not a fake one.
        info["error"] = f"Confirm-SecureBootUEFI invocation failed (often means legacy BIOS, not UEFI): {e}"
    return info


def run(target: str, **kwargs) -> dict:
    """hardware tool: Secure Boot Testing"""
    local_platform = platform.platform()
    local_node = platform.node()

    import os
    probe = _windows_secure_boot_probe() if os.name == "nt" else _linux_secure_boot_probe()

    return tool_result(
        "hardware.secure_boot_testing", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"Secure Boot testing against {target} requires firmware-level access to the "
                f"target's own UEFI NVRAM — this cannot be performed remotely/over the network. "
                f"(This machine's own Secure Boot probe: {probe.get('secure_boot_enabled', 'unknown')}.)",
        error="requires_hardware: no local/firmware access to the target's UEFI Secure Boot state",
        metadata={
            "note": f"The Secure Boot probe below describes the machine nexus-strike itself is "
                    f"running on ({local_node}), NOT {target} — it is diagnostic context only "
                    f"(proving the check is real), not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
            "local_secure_boot_probe": probe,
        },
    )


# Register with tool registry
tool_registry.register("hardware.secure_boot_testing", run, metadata={
    "name": "hardware.secure_boot_testing",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: real local Secure Boot state probe (mokutil --sb-state or Confirm-SecureBootUEFI) as diagnostic context; assessing a remote target's UEFI state requires firmware access, which this tool honestly reports it lacks",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
