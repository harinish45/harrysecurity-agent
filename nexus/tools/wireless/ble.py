#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Ble
Domain: wireless

Bluetooth Low Energy assessment (scanning advertisements, enumerating
peripherals/characteristics) requires a local BLE-capable radio driven
through a real BLE stack, physically in range of the target device — no
network-observable substitute exists. This previously ran `which <tool>` (a
no-op on Windows) against a hardcoded, WiFi-tool binary list unrelated to BLE
entirely, and always reported status "completed" with a canned note —
caught during this session's audit. Now it checks whether `bleak` (the
cross-platform BLE library) is importable, and:
  - if not, honestly reports STATUS_REQUIRES_HARDWARE;
  - if bleak is importable, it attempts a real, short, passive BLE
    advertisement scan of THIS host's RF neighborhood — if no usable adapter
    is present the scan itself fails and that failure is honestly reported
    as STATUS_REQUIRES_HARDWARE too; results are only ever the real devices
    bleak observed, never fabricated.
"""
from __future__ import annotations

import asyncio

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """wireless tool: Ble"""
    try:
        from bleak import BleakScanner
    except ImportError as exc:
        return tool_result(
            "wireless.ble", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"BLE assessment of {target} requires a local Bluetooth Low Energy "
                    f"adapter plus the `bleak` Python package — bleak is not installed, so no "
                    f"BLE radio can be driven from this host",
            error=f"requires_hardware: bleak not importable ({exc})",
        )

    timeout = float(kwargs.get("scan_timeout", 3.0))
    try:
        devices = asyncio.run(BleakScanner.discover(timeout=timeout))
    except Exception as exc:
        # bleak is installed but the actual BLE radio isn't present/usable
        # (no adapter, permissions denied, OS BLE stack unavailable, etc.)
        # — the "software present, hardware absent" case, still honestly
        # requires_hardware rather than fabricating a device list.
        return tool_result(
            "wireless.ble", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"bleak is installed but no usable BLE adapter was found on this host, so "
                    f"BLE scanning near {target} could not be performed",
            error=f"requires_hardware: BLE scan failed ({exc})",
        )

    findings = [
        Finding(
            title=f"BLE advertisement observed: {getattr(d, 'name', None) or 'unnamed'} ({d.address})",
            severity="info", confidence="high", affected_asset=d.address,
            evidence=f"address={d.address} name={getattr(d, 'name', None)} "
                     f"rssi={getattr(d, 'rssi', 'unknown')}",
            remediation="Confirm this device is in-scope before any further BLE interaction.",
            tool="wireless.ble",
        )
        for d in devices
    ]

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.ble", target,
        status=status,
        findings=findings,
        summary=f"Local BLE scan ({timeout}s) found {len(devices)} advertising device(s) in RF "
                f"range of this host. This reflects devices physically near the operator, not "
                f"necessarily {target} — BLE cannot be assessed over the network.",
        metadata={"scan_timeout": timeout, "device_count": len(devices)},
    )


# Register with tool registry
tool_registry.register("wireless.ble", run, metadata={
    "name": "wireless.ble",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: BLE assessment — checks whether the `bleak` BLE library is "
                    "importable, runs a real short passive advertisement scan through a usable "
                    "local adapter if so, and honestly reports requires_hardware if bleak is "
                    "missing or no adapter is usable rather than fabricating a device list",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
