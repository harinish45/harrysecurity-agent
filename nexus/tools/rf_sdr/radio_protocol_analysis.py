#!/usr/bin/env python3
"""
NEXUS-STRIKE — rf_sdr.radio_protocol_analysis
Domain: rf_sdr

Radio protocol analysis (identifying and decoding an over-the-air
protocol — e.g. LoRa, Zigbee, sub-GHz remotes) requires an SDR receiver
tuned to the target's actual transmission frequency, physically within RF
range — there's no network-observable substitute. This previously
reported a hardcoded tool-availability list unrelated to `target`, always
with status "completed" — caught during this session's audit
(byte-for-byte identical to jammer_detection.py, replay_testing.py, etc.
before this fix). Now it honestly reports STATUS_REQUIRES_HARDWARE.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs: Any) -> dict:
    """rf_sdr tool: radio protocol analysis prerequisite check."""
    return tool_result(
        "rf_sdr.radio_protocol_analysis", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"Radio protocol analysis against {target} requires an SDR receiver tuned to "
                f"the target's actual transmission frequency, physically within RF range, plus "
                f"captured IQ samples to decode — this cannot be performed remotely/over the "
                f"network",
        error="requires_hardware: no SDR receiver tuned to the target's transmission frequency",
        metadata={
            "note": "Decoding an over-the-air protocol requires the actual radio frequency and "
                    "modulation in use, which is not knowable from `target` alone without RF capture.",
        },
    )


tool_registry.register("rf_sdr.radio_protocol_analysis", run, metadata={
    "name": "rf_sdr.radio_protocol_analysis",
    "domain": "rf_sdr",
    "status": "requires_hardware",
    "description": "Radio protocol identification/decoding — requires SDR IQ capture physically near the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
