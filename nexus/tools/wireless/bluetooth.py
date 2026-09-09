#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Bluetooth
Domain: wireless

Classic Bluetooth assessment (device discovery, service enumeration) requires
a local Bluetooth radio driven through a real Bluetooth stack, physically in
range of the target device — no network-observable substitute exists. This
previously ran `which <tool>` (a no-op on Windows) against a hardcoded WiFi-
tool binary list unrelated to Bluetooth entirely, and always reported status
"completed" with a canned note — caught during this session's audit. Now it
checks whether PyBluez (`import bluetooth`) is importable, or falls back to a
platform-appropriate subprocess check for the BlueZ CLI (`bluetoothctl`/
`hcitool`), and:
  - if none are present, honestly reports STATUS_REQUIRES_HARDWARE;
  - if PyBluez is importable, it attempts a real classic-Bluetooth device
    discovery scan — a failure (no usable adapter) is honestly reported as
    STATUS_REQUIRES_HARDWARE too;
  - if only the BlueZ CLI is present, it does a real, read-only local
    controller listing (never an active scan) — results are only ever what
    was actually observed, never fabricated.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError


def run(target: str, **kwargs) -> dict:
    """wireless tool: Bluetooth"""
    try:
        import bluetooth as pybluez  # PyBluez classic-Bluetooth bindings
        has_pybluez = True
    except ImportError:
        pybluez = None
        has_pybluez = False

    bluetoothctl_path = shutil.which("bluetoothctl")
    hcitool_path = shutil.which("hcitool")

    if not has_pybluez and not bluetoothctl_path and not hcitool_path:
        return tool_result(
            "wireless.bluetooth", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Classic Bluetooth assessment of {target} requires a local Bluetooth "
                    f"adapter plus either the PyBluez Python package or the BlueZ CLI "
                    f"(bluetoothctl/hcitool) — none of these are present on this host",
            error="requires_hardware: no PyBluez, bluetoothctl, or hcitool available",
            metadata={
                "pybluez_importable": has_pybluez,
                "bluetoothctl": bluetoothctl_path,
                "hcitool": hcitool_path,
            },
        )

    if has_pybluez:
        try:
            duration = int(kwargs.get("scan_duration", 4))
            devices = pybluez.discover_devices(duration=duration, lookup_names=True)
        except Exception as exc:
            return tool_result(
                "wireless.bluetooth", target,
                status=STATUS_REQUIRES_HARDWARE,
                summary=f"PyBluez is installed but no usable Bluetooth adapter was found, so "
                        f"classic Bluetooth scanning near {target} could not be performed",
                error=f"requires_hardware: {exc}",
            )
        findings = [
            Finding(
                title=f"Bluetooth device observed: {name or 'unnamed'} ({addr})",
                severity="info", confidence="high", affected_asset=addr,
                evidence=f"address={addr} name={name}",
                remediation="Confirm this device is in-scope before any further interaction.",
                tool="wireless.bluetooth",
            )
            for addr, name in devices
        ]
        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            "wireless.bluetooth", target,
            status=status,
            findings=findings,
            summary=f"Local classic-Bluetooth scan found {len(devices)} device(s) in range of "
                    f"this host (not necessarily {target} — Bluetooth cannot be assessed over "
                    f"the network).",
            metadata={"device_count": len(devices)},
        )

    # No PyBluez, but a BlueZ CLI tool is present — read-only local
    # controller listing only, never triggers an active scan.
    cmd = [bluetoothctl_path, "list"] if bluetoothctl_path else [hcitool_path, "dev"]
    try:
        result = run_subprocess(cmd, timeout=10)
        output = result.stdout or ""
    except SandboxError as exc:
        return tool_result(
            "wireless.bluetooth", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Bluetooth CLI tooling is installed but failed to enumerate local "
                    f"controllers: {exc}",
            error=str(exc),
        )

    controllers = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    if controllers:
        findings.append(Finding(
            title="Local Bluetooth controller(s) detected",
            severity="info", confidence="high", affected_asset=target,
            evidence="\n".join(controllers[:20]),
            remediation="Confirm adapter capability before running an authorized Bluetooth "
                        "audit against the target.",
            tool="wireless.bluetooth",
        ))
    status = STATUS_COMPLETED if controllers else STATUS_NO_FINDINGS
    return tool_result(
        "wireless.bluetooth", target,
        status=status,
        findings=findings,
        summary=f"Bluetooth CLI tooling present; "
                f"{'found ' + str(len(controllers)) + ' local controller line(s)' if controllers else 'no local Bluetooth controllers enumerated'} "
                f"on this host. This lists LOCAL adapter capability only — it does not assess "
                f"{target} directly.",
        metadata={"raw_output_sample": output[:500]},
    )


# Register with tool registry
tool_registry.register("wireless.bluetooth", run, metadata={
    "name": "wireless.bluetooth",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: classic Bluetooth assessment — checks whether PyBluez is "
                    "importable or the BlueZ CLI is on PATH, runs a real device discovery scan "
                    "or read-only local controller listing if so, and honestly reports "
                    "requires_hardware if neither is available",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
