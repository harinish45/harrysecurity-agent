#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Dynamic Instrumentation
Domain: mobile

Dynamic instrumentation fundamentally requires a real attached
device/emulator and Frida — there's no network-observable substitute the
way HTTP/TLS/DNS-based tools have one. This previously ignored `target`
entirely and reported a DNS resolve + bare HTTP GET on `/` as if it were
dynamic instrumentation — always with status "completed" — caught during
an audit alongside hardware.usb_attacks. It now honestly reports
STATUS_REQUIRES_HARDWARE unless frida is installed AND a real USB
device/emulator is reachable, in which case it performs a real, safe,
read-only process enumeration (device.enumerate_processes()) — genuine
recon output, never fabricated.
"""
from __future__ import annotations

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_REQUIRES_HARDWARE,
    tool_result,
)
from nexus.tools.mobile._mobile_common import frida_status
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """mobile tool: dynamic instrumentation — requires-device honest
    degrade, with real read-only process enumeration when a device is
    attached."""
    status_info = frida_status()

    if not status_info["frida_python_installed"]:
        return tool_result(
            "mobile.dynamic_instrumentation", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Dynamic instrumentation of {target} requires the `frida` Python package plus a "
                    f"real attached device/emulator — neither is available here",
            error="requires_hardware: frida not installed",
            metadata=status_info,
        )

    if not status_info["device_attached"]:
        return tool_result(
            "mobile.dynamic_instrumentation", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Dynamic instrumentation of {target} requires a real attached device/emulator "
                    f"reachable via frida.get_usb_device() — none is currently attached",
            error="requires_hardware: no USB device reachable via frida",
            metadata=status_info,
        )

    try:
        import frida  # type: ignore

        device = frida.get_usb_device(timeout=1)
        processes = device.enumerate_processes()
    except Exception as e:
        return tool_result(
            "mobile.dynamic_instrumentation", target,
            status=STATUS_FAILED,
            summary=f"Device was detected but process enumeration failed: {e}",
            error=str(e),
            metadata=status_info,
        )

    proc_list = [{"pid": p.pid, "name": p.name} for p in processes]
    matching = [p for p in proc_list if isinstance(target, str) and target.lower() in p["name"].lower()]

    findings = [Finding(
        title=f"Live process list retrieved from attached device ({len(proc_list)} processes)",
        severity="info",
        confidence="certain",
        affected_asset=target,
        evidence=f"device_id={status_info['device_id']!r}; sample={[p['name'] for p in proc_list[:10]]}",
        remediation="Informational recon — attach an explicit Frida script to a chosen PID for actual "
                    "instrumentation (hooking, tracing), not performed automatically here.",
        tool="mobile.dynamic_instrumentation",
    )]
    if matching:
        findings.append(Finding(
            title=f"Target-matching process(es) currently running: {target}",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence=str(matching),
            remediation="",
            tool="mobile.dynamic_instrumentation",
        ))

    status = STATUS_COMPLETED if proc_list else STATUS_NO_FINDINGS
    return tool_result(
        "mobile.dynamic_instrumentation", target,
        status=status,
        findings=findings,
        summary=f"Enumerated {len(proc_list)} live process(es) on attached device "
                f"({status_info['device_name']}); {len(matching)} matching {target!r}",
        metadata={**status_info, "processes": proc_list},
    )


# Register with tool registry
tool_registry.register("mobile.dynamic_instrumentation", run, metadata={
    "name": "mobile.dynamic_instrumentation",
    "domain": "mobile",
    "status": "requires_hardware",
    "description": "Dynamic instrumentation recon — requires frida + a real attached device/emulator; "
                    "performs real read-only live process enumeration, never a fabricated result",
    "parameters": {
        "target": "Target app/process name to look for on the attached device",
    },
})
