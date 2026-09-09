#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Rubber Ducky Testing
Domain: hardware

Rubber Ducky / BadUSB HID-injection payload testing requires a
keystroke-injection device physically plugged into the target machine's
USB port — there's no network-observable substitute. (This is distinct
from hardware.usb_attacks, which covers broader USB attack surfaces such
as device-enumeration/driver attacks; this tool is specifically about HID
keystroke-injection payload delivery and detection.) This previously
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
    """hardware tool: Rubber Ducky Testing"""
    local_platform = platform.platform()
    local_node = platform.node()

    return tool_result(
        "hardware.rubber_ducky_testing", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"Rubber Ducky / HID-injection testing against {target} requires a "
                f"keystroke-injection USB device physically inserted into the target "
                f"machine's USB port — this cannot be performed remotely/over the network",
        error="requires_hardware: no HID-injection device plugged into the target",
        metadata={
            "note": f"The platform info below describes the machine nexus-strike itself is running "
                    f"on ({local_node}), NOT {target} — it is diagnostic context only, not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
        },
    )


# Register with tool registry
tool_registry.register("hardware.rubber_ducky_testing", run, metadata={
    "name": "hardware.rubber_ducky_testing",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: Rubber Ducky/BadUSB HID keystroke-injection testing — requires a physical injection device plugged into the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
