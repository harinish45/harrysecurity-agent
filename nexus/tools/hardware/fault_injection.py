#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Fault Injection
Domain: hardware

Fault injection (voltage/clock glitching, EM fault injection) requires a
fault-injection rig (e.g. ChipWhisperer, a glitch board) electrically
wired to the target's power/clock lines — there's no network-observable
substitute the way HTTP/TLS/DNS-based tools have one. This previously
ignored `target` entirely and reported the LOCAL machine's platform/USB
info as if it were an assessment of the target, always with status
"completed" — caught during this session's audit (byte-for-byte identical
to tpm_analysis.py, nfc_testing.py, etc. before this fix). Now it honestly
reports STATUS_REQUIRES_HARDWARE instead of fabricating target coverage.
"""
from __future__ import annotations

import platform

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """hardware tool: Fault Injection"""
    local_platform = platform.platform()
    local_node = platform.node()

    return tool_result(
        "hardware.fault_injection", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"Fault injection testing against {target} requires a fault-injection rig "
                f"(e.g. a ChipWhisperer or glitch board) electrically wired to the target "
                f"device's power/clock/reset lines — this cannot be performed remotely/over "
                f"the network",
        error="requires_hardware: no fault-injection rig wired to the target",
        metadata={
            "note": f"The platform info below describes the machine nexus-strike itself is running "
                    f"on ({local_node}), NOT {target} — it is diagnostic context only, not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
        },
    )


# Register with tool registry
tool_registry.register("hardware.fault_injection", run, metadata={
    "name": "hardware.fault_injection",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: fault injection (voltage/clock glitching) — requires a physical glitch rig wired to the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
