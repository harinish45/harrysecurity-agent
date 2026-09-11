#!/usr/bin/env python3
"""
NEXUS-STRIKE — iot.uart_analysis
Domain: iot

Previously a plain DNS-resolve + common-IoT-port scan (byte-for-byte
identical to can_bus_testing.py, jtag_analysis.py, embedded_linux.py, and
smart_device_assessment.py before this fix) — a UART is a physical serial
interface, not something a network scan can ever observe. Caught during
this session's audit.

Now: a real local serial-port enumeration via `pyserial`'s
`serial.tools.list_ports` (the standard, safe way to detect a UART-to-USB
adapter attached to *this* machine — pyserial is NOT in this environment's
requirements.txt/venv, verified during this fix). This can only ever
describe hardware attached to the machine nexus-strike itself runs on
(exactly like hardware.usb_attacks/tpm_analysis) — never `target`, since
UART access requires physically wiring RX/TX/GND to the target device's
debug header.
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


def run(target: str, **kwargs: Any) -> dict:
    """iot tool: real local serial-port enumeration via pyserial (diagnostic only, not target-specific)."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return tool_result(
            "iot.uart_analysis", target,
            status=STATUS_UNAVAILABLE,
            summary=f"UART analysis of {target} requires pyserial to enumerate local serial "
                    f"adapters (and physical RX/TX/GND wiring to the target's debug header) — "
                    f"pyserial is not installed in this environment",
            error="unavailable: pyserial not installed (pip install pyserial)",
        )

    ports = list(list_ports.comports())
    port_info = [{"device": p.device, "description": p.description, "hwid": p.hwid} for p in ports]

    if not ports:
        return tool_result(
            "iot.uart_analysis", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"UART analysis of {target} requires a UART-to-USB adapter physically wired "
                    f"to the target device's RX/TX/GND debug header — no serial adapters are "
                    f"attached to this machine",
            error="requires_hardware: no serial ports detected on this machine",
            metadata={"note": "This lists ports on the machine nexus-strike runs on, NOT target.", "local_ports": port_info},
        )

    findings = [Finding(
        title=f"{len(ports)} local serial port(s) detected",
        severity="info", confidence="certain",
        affected_asset="local UART hardware",
        evidence=str(port_info),
        remediation="This describes hardware on the machine running nexus-strike, not target — "
                    "wire one of these adapters to the target device's UART header to actually analyze it.",
        tool="iot.uart_analysis",
    )]

    return tool_result(
        "iot.uart_analysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"{len(ports)} local serial port(s) available for UART work (not yet wired to {target})",
        metadata={"note": "local diagnostic only, not a target assessment", "local_ports": port_info},
    )


tool_registry.register("iot.uart_analysis", run, metadata={
    "name": "iot.uart_analysis",
    "domain": "iot",
    "status": "requires_hardware",
    "description": "Real local serial-port enumeration via pyserial (diagnostic); UART analysis of a target requires physical wiring, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
