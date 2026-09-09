#!/usr/bin/env python3
"""
NEXUS-STRIKE — iot.jtag_analysis
Domain: iot

Previously a plain DNS-resolve + common-IoT-port scan (byte-for-byte
identical to uart_analysis.py, can_bus_testing.py, embedded_linux.py, and
smart_device_assessment.py before this fix) — JTAG is a physical debug
interface, not something a network scan can ever observe. Caught during
this session's audit.

Now: a real local USB-device enumeration via `pyusb` (checked for
importability — NOT in this environment's requirements.txt/venv, verified
during this fix), matching connected devices against a table of common
JTAG/SWD adapter USB VID:PID pairs (J-Link, ST-Link, FTDI FT2232/FT232H —
widely used as JTAG bit-bangers, Bus Blaster, Black Magic Probe). This can
only ever describe hardware attached to the machine nexus-strike itself
runs on — never `target`, since JTAG access requires physically attaching
test-clip/pogo-pin probes to the target board's TDI/TDO/TCK/TMS pads.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_REQUIRES_HARDWARE,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

# (vendor, product) USB VID:PID pairs for common JTAG/SWD adapters.
_JTAG_ADAPTER_VIDPIDS: dict[tuple[int, int], str] = {
    (0x1366, 0x0101): "SEGGER J-Link",
    (0x1366, 0x1015): "SEGGER J-Link",
    (0x0483, 0x3748): "ST-Link/V2",
    (0x0483, 0x374B): "ST-Link/V2-1",
    (0x0403, 0x6010): "FTDI FT2232 (common JTAG bit-banger, e.g. Bus Blaster)",
    (0x0403, 0x6014): "FTDI FT232H (common JTAG bit-banger)",
    (0x1D50, 0x6018): "Black Magic Probe",
}


def run(target: str, **kwargs: Any) -> dict:
    """iot tool: real local USB VID:PID scan for known JTAG/SWD adapters (diagnostic only)."""
    try:
        import usb.core
    except ImportError:
        return tool_result(
            "iot.jtag_analysis", target,
            status=STATUS_UNAVAILABLE,
            summary=f"JTAG analysis of {target} requires pyusb to enumerate local USB JTAG/SWD "
                    f"adapters (and physical TDI/TDO/TCK/TMS probe contact with the target's "
                    f"debug pads) — pyusb is not installed in this environment",
            error="unavailable: pyusb not installed (pip install pyusb)",
        )

    try:
        devices = list(usb.core.find(find_all=True))
    except usb.core.NoBackendError as e:
        return tool_result(
            "iot.jtag_analysis", target,
            status=STATUS_UNAVAILABLE,
            summary=f"pyusb is installed but no libusb backend is available on this machine: {e}",
            error=f"unavailable: {e}",
        )

    found = []
    for dev in devices:
        key = (dev.idVendor, dev.idProduct)
        if key in _JTAG_ADAPTER_VIDPIDS:
            found.append({"vid": hex(dev.idVendor), "pid": hex(dev.idProduct), "name": _JTAG_ADAPTER_VIDPIDS[key]})

    if not found:
        return tool_result(
            "iot.jtag_analysis", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"JTAG analysis of {target} requires a JTAG/SWD adapter (J-Link/ST-Link/FTDI "
                    f"bit-banger/Black Magic Probe) physically probing the target board's debug "
                    f"pads — no known JTAG adapter VID:PID found among {len(devices)} local USB device(s)",
            error="requires_hardware: no JTAG/SWD adapter detected on this machine's USB bus",
            metadata={"note": "This scans USB devices on the machine nexus-strike runs on, NOT target.", "usb_devices_scanned": len(devices)},
        )

    findings = [Finding(
        title=f"{len(found)} known JTAG/SWD adapter(s) detected on local USB bus",
        severity="info", confidence="certain",
        affected_asset="local JTAG hardware",
        evidence=str(found),
        remediation="This describes hardware on the machine running nexus-strike, not target — "
                    "physically probe the target's debug pads with one of these adapters to actually analyze it.",
        tool="iot.jtag_analysis",
    )]

    return tool_result(
        "iot.jtag_analysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"{len(found)} JTAG/SWD adapter(s) available locally (not yet probing {target})",
        metadata={"note": "local diagnostic only, not a target assessment", "adapters_found": found},
    )


tool_registry.register("iot.jtag_analysis", run, metadata={
    "name": "iot.jtag_analysis",
    "domain": "iot",
    "status": "requires_hardware",
    "description": "Real local USB VID:PID scan for known JTAG/SWD adapters via pyusb (diagnostic); JTAG analysis of a target requires physical probing, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
