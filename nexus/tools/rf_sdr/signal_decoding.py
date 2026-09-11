#!/usr/bin/env python3
"""
NEXUS-STRIKE — rf_sdr.signal_decoding
Domain: rf_sdr

Signal decoding (demodulating captured IQ samples into bits/bytes — ASK,
FSK, OOK, etc.) requires an actual RF capture from an SDR receiver
physically within range of the target's transmitter — there's no
network-observable substitute. This previously reported a hardcoded
tool-availability list unrelated to `target`, always with status
"completed" — caught during this session's audit (byte-for-byte identical
to jammer_detection.py, replay_testing.py, etc. before this fix). Now it
honestly reports STATUS_REQUIRES_HARDWARE, unless real IQ sample data is
explicitly supplied via kwargs.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs: Any) -> dict:
    """rf_sdr tool: signal decoding prerequisite check."""
    return tool_result(
        "rf_sdr.signal_decoding", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"Signal decoding against {target} requires captured IQ sample data from an SDR "
                f"receiver physically within range of the target's transmitter — no capture "
                f"file was supplied and this cannot be produced remotely/over the network",
        error="requires_hardware: no IQ capture data available for target's actual transmission",
        metadata={
            "note": "Pass a real IQ capture file (e.g. iq_capture_path=) to decode previously "
                    "captured samples; this tool does not fabricate demodulated output without one.",
        },
    )


tool_registry.register("rf_sdr.signal_decoding", run, metadata={
    "name": "rf_sdr.signal_decoding",
    "domain": "rf_sdr",
    "status": "requires_hardware",
    "description": "RF signal demodulation/decoding — requires a real IQ capture from hardware physically near the target, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
        "iq_capture_path": "Optional path to a real IQ capture file to decode",
    },
})
