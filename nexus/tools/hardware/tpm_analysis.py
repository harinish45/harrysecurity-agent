#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Tpm Analysis
Domain: hardware

TPM (Trusted Platform Module) analysis fundamentally requires physical
access to the actual target's TPM chip — there's no network-observable
substitute. This previously reported generic `platform.platform()` /
`lsusb` output as if it were a TPM assessment, always with status
"completed" — caught during this session's audit (byte-for-byte identical
to fault_injection.py, nfc_testing.py, etc.).

Now it performs a REAL, read-only TPM presence/version query against
whatever machine nexus-strike itself is running on (Linux: presence of
/dev/tpm0 or /dev/tpmrm0 plus /sys/class/tpm/tpm0 capability files;
Windows: `Get-Tpm` via PowerShell) and reports that honestly as local
diagnostic context — never as an assessment of `target`, since assessing a
*remote* target's TPM requires physical proximity to that target's
hardware, which this tool does not have.
"""
from __future__ import annotations

import os
import platform

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import SandboxError, run_subprocess


def _linux_tpm_probe() -> dict:
    info: dict = {"tpm_device_present": False}
    for dev in ("/dev/tpmrm0", "/dev/tpm0"):
        if os.path.exists(dev):
            info["tpm_device_present"] = True
            info["tpm_device_path"] = dev
            break
    sysfs_base = "/sys/class/tpm/tpm0"
    if os.path.isdir(sysfs_base):
        for fname in ("tpm_version_major", "caps"):
            path = os.path.join(sysfs_base, fname)
            try:
                if os.path.isfile(path):
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        info[fname] = f.read().strip()[:500]
            except OSError:
                pass
    return info


def _windows_tpm_probe() -> dict:
    info: dict = {"tpm_device_present": False}
    try:
        result = run_subprocess(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Tpm | Format-List *"],
            timeout=15,
        )
        output = (result.stdout or "").strip()
        if output:
            info["get_tpm_output"] = output[:1500]
            info["tpm_device_present"] = "TpmPresent" in output and "True" in output
    except (SandboxError, FileNotFoundError, OSError) as e:
        info["error"] = f"Get-Tpm invocation failed: {e}"
    return info


def run(target: str, **kwargs) -> dict:
    """hardware tool: Tpm Analysis"""
    local_platform = platform.platform()
    local_node = platform.node()

    if os.name == "nt":
        probe = _windows_tpm_probe()
    else:
        probe = _linux_tpm_probe()

    tpm_present = probe.get("tpm_device_present", False)

    return tool_result(
        "hardware.tpm_analysis", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"TPM analysis against {target} requires physical/firmware-level access to the "
                f"target's own TPM chip — this cannot be performed remotely/over the network. "
                f"(This machine's own TPM presence: {tpm_present}.)",
        error="requires_hardware: no local access to the target's TPM",
        metadata={
            "note": f"The TPM probe below describes the machine nexus-strike itself is running "
                    f"on ({local_node}), NOT {target} — it is diagnostic context only (proving "
                    f"the check is real and read-only), not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
            "local_tpm_probe": probe,
        },
    )


# Register with tool registry
tool_registry.register("hardware.tpm_analysis", run, metadata={
    "name": "hardware.tpm_analysis",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: real local TPM presence/version probe (/dev/tpm0 or Get-Tpm) as diagnostic context; assessing a remote target's TPM requires physical access, which this tool honestly reports it lacks",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
