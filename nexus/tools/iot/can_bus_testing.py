#!/usr/bin/env python3
"""
NEXUS-STRIKE — iot.can_bus_testing
Domain: iot

Previously a plain DNS-resolve + common-IoT-port scan (byte-for-byte
identical to uart_analysis.py, jtag_analysis.py, embedded_linux.py, and
smart_device_assessment.py before this fix) — CAN bus is a physical
automotive/industrial serial bus, not something a network scan can ever
observe. Caught during this session's audit.

Now: a real local serial/CAN-adapter enumeration via `pyserial`'s
`serial.tools.list_ports` (the standard way to detect a USB-CAN or
UART-based CAN adapter attached to *this* machine — pyserial is NOT in
this environment's requirements.txt/venv, verified during this fix), with
a check for common CAN-adapter description strings (SocketCAN/Kvaser/
PCAN/CANtact/USB2CAN). This can only ever describe hardware attached to
the machine nexus-strike itself runs on — never `target`, since CAN bus
access requires physically tapping into the target vehicle/device's CAN
H/L lines.
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

_CAN_ADAPTER_MARKERS = ("can", "kvaser", "pcan", "cantact", "socketcan", "usb2can", "canable")


def run(target: str, **kwargs: Any) -> dict:
    """iot tool: real local CAN/serial-adapter enumeration via pyserial (diagnostic only)."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return tool_result(
            "iot.can_bus_testing", target,
            status=STATUS_UNAVAILABLE,
            summary=f"CAN bus testing of {target} requires pyserial to enumerate local CAN/serial "
                    f"adapters (and physical CAN-H/CAN-L wiring to the target bus) — pyserial is "
                    f"not installed in this environment",
            error="unavailable: pyserial not installed (pip install pyserial)",
        )

    ports = list(list_ports.comports())
    port_info = [{"device": p.device, "description": p.description, "hwid": p.hwid} for p in ports]
    can_like = [p for p in port_info if any(m in (p["description"] or "").lower() for m in _CAN_ADAPTER_MARKERS)]

    if not ports:
        return tool_result(
            "iot.can_bus_testing", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"CAN bus testing of {target} requires a CAN adapter (SocketCAN/Kvaser/PCAN/"
                    f"CANtact/etc.) physically wired to the target's CAN-H/CAN-L bus lines — no "
                    f"serial/CAN adapters are attached to this machine",
            error="requires_hardware: no serial/CAN adapters detected on this machine",
            metadata={"note": "This lists ports on the machine nexus-strike runs on, NOT target.", "local_ports": port_info},
        )

    findings = [Finding(
        title=f"{len(ports)} local serial port(s) detected ({len(can_like)} CAN-adapter-like)",
        severity="info", confidence="certain",
        affected_asset="local CAN/serial hardware",
        evidence=str(port_info),
        remediation="This describes hardware on the machine running nexus-strike, not target — "
                    "wire a CAN adapter to the target's CAN-H/CAN-L lines to actually test it.",
        tool="iot.can_bus_testing",
    )]

    return tool_result(
        "iot.can_bus_testing", target,
        status=STATUS_COMPLETED if can_like else STATUS_REQUIRES_HARDWARE,
        findings=findings,
        summary=f"{len(ports)} local serial port(s) ({len(can_like)} CAN-adapter-like) available "
                f"(not yet wired to {target}'s CAN bus)",
        metadata={"note": "local diagnostic only, not a target assessment", "local_ports": port_info, "can_like_ports": can_like},
    )


tool_registry.register("iot.can_bus_testing", run, metadata={
    "name": "iot.can_bus_testing",
    "domain": "iot",
    "status": "requires_hardware",
    "description": "Real local CAN/serial-adapter enumeration via pyserial (diagnostic); CAN bus testing of a target requires physical wiring, cannot run remotely",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
