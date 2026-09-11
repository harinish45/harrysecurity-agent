#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Rfid Testing
Domain: hardware

RFID testing (badge cloning, Proxmark3/RFID-reader-based attacks) requires
an RFID reader/transceiver physically proximate to the actual target — no
network-observable substitute exists. This previously ignored `target`
entirely and reported the LOCAL machine's platform/USB info as if it were
an assessment of the target, always with status "completed" — caught
during this session's audit (byte-for-byte identical to usb_attacks.py).
Now it honestly reports STATUS_REQUIRES_HARDWARE instead of fabricating
target coverage.
"""
import os
import platform

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """hardware tool: Rfid Testing"""
    local_platform = platform.platform()
    local_node = platform.node()
    try:
        lsusb_output = os.popen("lsusb 2>/dev/null || echo 'lsusb not available'").read()[:200]
    except OSError:
        lsusb_output = "lsusb not available"

    return tool_result(
        "hardware.rfid_testing", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"RFID testing against {target} requires a physical RFID reader/transceiver "
                f"(e.g. a Proxmark3) proximate to the target — this cannot be performed remotely/over the network",
        error="requires_hardware: no RFID reader available",
        metadata={
            "note": f"The platform info below describes the machine nexus-strike itself is running "
                    f"on ({local_node}), NOT {target} — it is diagnostic context only, not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
            "local_lsusb_sample": lsusb_output,
        },
    )


# Register with tool registry
tool_registry.register("hardware.rfid_testing", run, metadata={
    "name": "hardware.rfid_testing",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: RFID testing — requires a physical RFID reader against the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
