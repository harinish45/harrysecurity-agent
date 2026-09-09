#!/usr/bin/env python3
"""
NEXUS-STRIKE — rf_sdr.rtl_sdr_analysis
Domain: rf_sdr

RF/SDR signal analysis fundamentally requires an attached SDR receiver
(antenna in RF range of the actual target) — there's no
network-observable substitute. This previously reported which of a
hardcoded tool list was "available"/"not installed" via `which`, always
with status "completed" regardless of whether any SDR hardware was
actually present or `target` was ever used — caught during this session's
audit (byte-for-byte identical to hackrf_experimentation.py before this
fix).

Now: a real prerequisite check for `rtl_test`/`rtl_sdr` on PATH via
`shutil.which`. If found, a real, safe, read-only `rtl_test -t` invocation
(device enumeration/tuner test, no RF capture) is run and its output is
the finding. If absent — the expected case on this dev machine, which has
no RTL-SDR hardware — this honestly reports STATUS_REQUIRES_HARDWARE
instead of fabricating an analysis of `target`.
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
    """rf_sdr tool: real rtl_test prerequisite check + safe device-enumeration probe."""
    rtl_test_path = shutil.which("rtl_test")
    rtl_sdr_path = shutil.which("rtl_sdr")

    if not rtl_test_path and not rtl_sdr_path:
        return tool_result(
            "rf_sdr.rtl_sdr_analysis", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"RTL-SDR analysis against {target} requires an attached RTL-SDR dongle "
                    f"(and the rtl-sdr tools on PATH) within RF range of the target — neither "
                    f"is present on this machine",
            error="requires_hardware: rtl_test/rtl_sdr not found on PATH, no RTL-SDR dongle detected",
            metadata={"rtl_test_on_path": False, "rtl_sdr_on_path": False},
        )

    try:
        result = run_subprocess([rtl_test_path or rtl_sdr_path, "-t"], timeout=10)
        output = (result.stdout or "")[:1000]
    except (SandboxError, FileNotFoundError, OSError) as e:
        return tool_result(
            "rf_sdr.rtl_sdr_analysis", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"rtl_test is on PATH but device enumeration failed — no RTL-SDR dongle attached: {e}",
            error=f"requires_hardware: {e}",
            metadata={"rtl_test_on_path": bool(rtl_test_path), "rtl_sdr_on_path": bool(rtl_sdr_path)},
        )

    findings = [Finding(
        title="RTL-SDR device enumeration executed (rtl_test -t)",
        severity="info",
        confidence="certain",
        affected_asset="local RF hardware",
        evidence=output or "(no output — no device found)",
        remediation="This is diagnostic-only local hardware enumeration, not an assessment of "
                    "target's RF emissions (RF work requires physical proximity to the target).",
        tool="rf_sdr.rtl_sdr_analysis",
    )]

    return tool_result(
        "rf_sdr.rtl_sdr_analysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"rtl_test tools present; ran real device-enumeration probe (target {target} "
                f"itself was not RF-analyzed — that requires physical antenna proximity)",
        metadata={"rtl_test_on_path": bool(rtl_test_path), "rtl_sdr_on_path": bool(rtl_sdr_path), "raw_output": output},
    )


tool_registry.register("rf_sdr.rtl_sdr_analysis", run, metadata={
    "name": "rf_sdr.rtl_sdr_analysis",
    "domain": "rf_sdr",
    "status": "requires_hardware",
    "description": "Real rtl_test/rtl_sdr PATH prerequisite check + safe device-enumeration probe when present; honest requires_hardware degrade otherwise",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
