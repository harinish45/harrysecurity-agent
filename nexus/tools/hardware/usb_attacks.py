#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Usb Attacks
Domain: hardware

USB attack testing (BadUSB/Rubber-Ducky-style payload delivery, USB device
enumeration attacks) fundamentally requires a physical USB device
attached to or proximate to the actual target — there's no network-
observable substitute the way HTTP/TLS/DNS-based tools have one. This
previously ignored `target` entirely and reported the LOCAL machine's
platform/USB info as if it were an assessment of the target, always with
status "completed" — caught during this session's audit. Now it honestly
reports STATUS_REQUIRES_HARDWARE instead of fabricating target coverage.
"""
import os
import platform

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """hardware tool: Usb Attacks"""
    local_platform = platform.platform()
    local_node = platform.node()
    try:
        lsusb_output = os.popen("lsusb 2>/dev/null || echo 'lsusb not available'").read()[:200]
    except OSError:
        lsusb_output = "lsusb not available"

    return tool_result(
        "hardware.usb_attacks", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"USB attack testing against {target} requires a physical USB device "
                f"(e.g. a BadUSB/Rubber Ducky) attached to or proximate to the target — "
                f"this cannot be performed remotely/over the network",
        error="requires_hardware: no physical USB delivery vector available",
        metadata={
            "note": f"The platform info below describes the machine nexus-strike itself is running "
                    f"on ({local_node}), NOT {target} — it is diagnostic context only, not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
            "local_lsusb_sample": lsusb_output,
        },
    )


# Register with tool registry
tool_registry.register("hardware.usb_attacks", run, metadata={
    "name": "hardware.usb_attacks",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: USB attack testing — requires a physical USB device against the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
