#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Lora
Domain: wireless

LoRa assessment (sniffing/interacting with a target's LoRaWAN traffic)
requires a LoRa radio (e.g. an RN2483/SX127x module) attached over a serial/
USB interface — no network-observable substitute exists. This previously ran
`which <tool>` (a no-op on Windows) against a hardcoded WiFi-tool binary list
unrelated to LoRa entirely, and always reported status "completed" with a
canned note — caught during this session's audit. Now it checks whether
`pyserial` is importable and, if so, does a real, read-only enumeration of
serial/USB ports attached to this host via `serial.tools.list_ports`:
  - if pyserial isn't installed, or no serial ports are present, it honestly
    reports STATUS_REQUIRES_HARDWARE;
  - if serial ports are found, they're reported as *candidate* devices only
    — pyserial can enumerate ports, not confirm LoRa protocol support, so
    this never claims a port IS a LoRa radio, only that it exists and needs
    manual confirmation.
"""
from __future__ import annotations

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """wireless tool: Lora"""
    try:
        from serial.tools import list_ports
    except ImportError as exc:
        return tool_result(
            "wireless.lora", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"LoRa assessment of {target} requires a LoRa radio (e.g. an RN2483/"
                    f"SX127x module) attached over a serial/USB interface, and the `pyserial` "
                    f"package to enumerate it — pyserial is not installed",
            error=f"requires_hardware: pyserial not importable ({exc})",
        )

    ports = list(list_ports.comports())
    if not ports:
        return tool_result(
            "wireless.lora", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"pyserial is installed but no serial/USB devices are attached to this "
                    f"host, so no candidate LoRa radio is available to assess {target}",
            error="requires_hardware: no serial ports enumerated",
        )

    findings = [
        Finding(
            title=f"Serial device detected: {p.device}",
            severity="info", confidence="low", affected_asset=p.device,
            evidence=f"device={p.device} description={p.description!r} hwid={p.hwid!r}",
            remediation="Manually confirm whether this serial device is a LoRa radio module "
                        "(e.g. by querying firmware/AT commands) before attempting any RF "
                        "operations against it.",
            tool="wireless.lora",
        )
        for p in ports
    ]

    return tool_result(
        "wireless.lora", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Found {len(findings)} serial device(s) attached to this host that could be a "
                f"LoRa radio — pyserial can only enumerate serial ports, not confirm LoRa "
                f"protocol support, so manual verification is required. This does not assess "
                f"{target} directly.",
        metadata={"port_count": len(findings)},
    )


# Register with tool registry
tool_registry.register("wireless.lora", run, metadata={
    "name": "wireless.lora",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: LoRa assessment — checks whether pyserial is importable and "
                    "enumerates real serial/USB ports on this host as LoRa-radio candidates if "
                    "so (never claims a port IS a LoRa radio without manual confirmation), and "
                    "honestly reports requires_hardware if pyserial is missing or no ports exist",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
