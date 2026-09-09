#!/usr/bin/env python3
"""
NEXUS-STRIKE — hardware tool: Side Channel Analysis
Domain: hardware

Side-channel analysis (power analysis / SPA-DPA, EM emanation capture,
timing analysis against a physical device) requires an oscilloscope or
power/EM probe physically attached to the target device's power rail or
antenna — there's no network-observable substitute. This previously
ignored `target` entirely and reported the LOCAL machine's platform/USB
info as if it were an assessment of the target, always with status
"completed" — caught during this session's audit (byte-for-byte identical
to tpm_analysis.py, fault_injection.py, etc. before this fix). Now it
honestly reports STATUS_REQUIRES_HARDWARE instead of fabricating target
coverage.
"""
from __future__ import annotations

import platform

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """hardware tool: Side Channel Analysis"""
    local_platform = platform.platform()
    local_node = platform.node()

    return tool_result(
        "hardware.side_channel_analysis", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"Side-channel analysis against {target} requires an oscilloscope or power/EM "
                f"probe physically attached to the target device's power rail, ground plane, "
                f"or antenna to capture power/EM/timing traces — this cannot be performed "
                f"remotely/over the network",
        error="requires_hardware: no oscilloscope/power probe attached to the target",
        metadata={
            "note": f"The platform info below describes the machine nexus-strike itself is running "
                    f"on ({local_node}), NOT {target} — it is diagnostic context only, not a target assessment.",
            "local_platform": local_platform,
            "local_node": local_node,
        },
    )


# Register with tool registry
tool_registry.register("hardware.side_channel_analysis", run, metadata={
    "name": "hardware.side_channel_analysis",
    "domain": "hardware",
    "status": "requires_hardware",
    "description": "hardware tool: power/EM/timing side-channel analysis — requires an oscilloscope or probe physically attached to the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
