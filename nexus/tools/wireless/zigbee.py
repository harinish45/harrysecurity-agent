#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Zigbee
Domain: wireless

Zigbee assessment (sniffing/interacting with a target's Zigbee network)
requires a Zigbee radio (e.g. an EZSP/Silicon Labs coordinator dongle)
attached over a serial/USB interface plus the zigpy/bellows Python stack to
speak the protocol to it — no network-observable substitute exists. This
previously ran `which <tool>` (a no-op on Windows) against a hardcoded
WiFi-tool binary list unrelated to Zigbee entirely, and always reported
status "completed" with a canned note — caught during this session's audit.
Now it checks whether `pyserial` AND the `zigpy`/`bellows` packages are
importable, and:
  - if either is missing, honestly reports STATUS_REQUIRES_HARDWARE naming
    exactly what's absent;
  - if both are present, it does a real, read-only enumeration of serial/USB
    ports attached to this host via `serial.tools.list_ports` — reported as
    *candidate* Zigbee coordinator devices only, since enumeration alone
    can't confirm the Zigbee protocol without actually opening the radio.
"""
from __future__ import annotations

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """wireless tool: Zigbee"""
    try:
        from serial.tools import list_ports
        has_pyserial = True
    except ImportError:
        list_ports = None
        has_pyserial = False

    zigpy_stack_installed = False
    try:
        import zigpy  # noqa: F401
        import bellows  # noqa: F401
        zigpy_stack_installed = True
    except ImportError:
        pass

    if not has_pyserial or not zigpy_stack_installed:
        missing = []
        if not has_pyserial:
            missing.append("pyserial")
        if not zigpy_stack_installed:
            missing.append("zigpy/bellows")
        return tool_result(
            "wireless.zigbee", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Zigbee assessment of {target} requires a Zigbee radio (e.g. an EZSP/"
                    f"Silicon Labs coordinator dongle) on a serial/USB interface plus the "
                    f"zigpy/bellows Python stack to speak the Zigbee protocol to it — missing: "
                    f"{', '.join(missing)}",
            error=f"requires_hardware: missing dependencies ({', '.join(missing)})",
            metadata={"pyserial_installed": has_pyserial, "zigpy_stack_installed": zigpy_stack_installed},
        )

    ports = list(list_ports.comports())
    if not ports:
        return tool_result(
            "wireless.zigbee", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"pyserial and the zigpy/bellows stack are installed but no serial/USB "
                    f"devices are attached to this host, so no candidate Zigbee coordinator is "
                    f"available to assess {target}",
            error="requires_hardware: no serial ports enumerated",
        )

    findings = [
        Finding(
            title=f"Serial device detected: {p.device}",
            severity="info", confidence="low", affected_asset=p.device,
            evidence=f"device={p.device} description={p.description!r} hwid={p.hwid!r}",
            remediation="Manually confirm whether this serial device is a Zigbee coordinator "
                        "(e.g. by opening it with bellows/zigpy) before attempting any RF "
                        "operations against it.",
            tool="wireless.zigbee",
        )
        for p in ports
    ]

    return tool_result(
        "wireless.zigbee", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Found {len(findings)} serial device(s) attached to this host that could be a "
                f"Zigbee coordinator — enumeration alone can't confirm Zigbee protocol support "
                f"without actually opening the radio, so manual verification is required. This "
                f"does not assess {target} directly.",
        metadata={"port_count": len(findings)},
    )


# Register with tool registry
tool_registry.register("wireless.zigbee", run, metadata={
    "name": "wireless.zigbee",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: Zigbee assessment — checks whether pyserial AND zigpy/"
                    "bellows are importable, enumerates real serial/USB ports on this host as "
                    "Zigbee-coordinator candidates if so, and honestly reports "
                    "requires_hardware naming exactly what's missing otherwise",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
