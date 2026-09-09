#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Nfc Testing
Domain: hardware

NFC testing (tag emulation/cloning, relay attacks against NFC-based access
control) requires an NFC reader/transceiver (e.g. a PN532 or ACR122U)
physically proximate to the actual target device — there's no
network-observable substitute. This previously ignored `target` entirely
and reported the LOCAL machine's platform/USB info as if it were an
assessment of the target, always with status "completed" — caught during
this session's audit (byte-for-byte identical to tpm_analysis.py,
fault_injection.py, etc. before this fix). Now it honestly reports
STATUS_REQUIRES_HARDWARE instead of fabricating target coverage.
"""
from __future__ import annotations

import platform

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """hardware tool: Nfc Testing"""
    local_platform = platform.platform()
    local_node = platform.node()

    return tool_result(
        "hardware.nfc_testing", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"NFC testing against {target} requires an NFC reader/transceiver (e.g. a "
                f"PN532 or ACR122U) physically proximate to the target device — this cannot "
                f"be performed remotely/over the network",
        error="requires_hardware: no NFC reader/transceiver available",
        metadata={
            "note": f"The platform info below describes the machine nexus-strike itself is running "
                    f"on ({local_node}), NOT {target} — it is diagnostic context only, not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
        },
    )


# Register with tool registry
tool_registry.register("hardware.nfc_testing", run, metadata={
    "name": "hardware.nfc_testing",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: NFC tag/reader testing — requires a physical NFC transceiver near the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
