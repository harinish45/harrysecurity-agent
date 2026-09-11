#!/usr/bin/env python3
"""
NEXUS-STRIKE — rf_sdr.hackrf_experimentation
Domain: rf_sdr

RF/SDR signal analysis fundamentally requires an attached SDR transceiver
(antenna in RF range of the actual target) — there's no
network-observable substitute. This previously reported which of a
hardcoded tool list was "available"/"not installed" via `which`, always
with status "completed" regardless of whether any SDR hardware was
actually present or `target` was ever used — caught during this session's
audit (byte-for-byte identical to rtl_sdr_analysis.py before this fix).

Now: a real prerequisite check for `hackrf_info` on PATH via
`shutil.which`. If found, a real, safe, read-only, no-args `hackrf_info`
invocation (device enumeration only, no RF transmission/capture) is run
and its output is the finding. If absent — the expected case on this dev
machine, which has no HackRF hardware — this honestly reports
STATUS_REQUIRES_HARDWARE instead of fabricating an analysis of `target`.
"""
from __future__ import annotations

import shutil
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_REQUIRES_HARDWARE,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import SandboxError, run_subprocess


def run(target: str, **kwargs: Any) -> dict:
    """rf_sdr tool: real hackrf_info prerequisite check + safe device-enumeration probe."""
    hackrf_info_path = shutil.which("hackrf_info")

    if not hackrf_info_path:
        return tool_result(
            "rf_sdr.hackrf_experimentation", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"HackRF experimentation against {target} requires an attached HackRF "
                    f"transceiver (and hackrf_info on PATH) within RF range of the target — "
                    f"neither is present on this machine",
            error="requires_hardware: hackrf_info not found on PATH, no HackRF device detected",
            metadata={"hackrf_info_on_path": False},
        )

    try:
        result = run_subprocess([hackrf_info_path], timeout=10)
        output = (result.stdout or "")[:1000]
    except (SandboxError, FileNotFoundError, OSError) as e:
        return tool_result(
            "rf_sdr.hackrf_experimentation", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"hackrf_info is on PATH but device enumeration failed — no HackRF attached: {e}",
            error=f"requires_hardware: {e}",
            metadata={"hackrf_info_on_path": True},
        )

    findings = [Finding(
        title="HackRF device enumeration executed (hackrf_info)",
        severity="info",
        confidence="certain",
        affected_asset="local RF hardware",
        evidence=output or "(no output — no device found)",
        remediation="This is diagnostic-only local hardware enumeration, not an assessment of "
                    "target's RF emissions (RF work requires physical antenna proximity).",
        tool="rf_sdr.hackrf_experimentation",
    )]

    return tool_result(
        "rf_sdr.hackrf_experimentation", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"hackrf_info tools present; ran real device-enumeration probe (target {target} "
                f"itself was not RF-analyzed — that requires physical antenna proximity)",
        metadata={"hackrf_info_on_path": True, "raw_output": output},
    )


tool_registry.register("rf_sdr.hackrf_experimentation", run, metadata={
    "name": "rf_sdr.hackrf_experimentation",
    "domain": "rf_sdr",
    "status": "requires_hardware",
    "description": "Real hackrf_info PATH prerequisite check + safe device-enumeration probe when present; honest requires_hardware degrade otherwise",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
