#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Cert Pinning Bypass
Domain: mobile

Certificate-pinning bypass fundamentally requires a real attached
device/emulator and Frida — there's no network-observable substitute the
way HTTP/TLS/DNS-based tools have one. This previously ignored `target`
entirely and reported a DNS resolve + bare HTTP GET on `/` as if it were a
pinning-bypass attempt — always with status "completed" — caught during an
audit alongside hardware.usb_attacks. It now honestly reports
STATUS_REQUIRES_HARDWARE unless frida is installed AND a real USB
device/emulator is reachable, in which case it performs a real, safe,
read-only device enumeration (frida.get_usb_device()) — it never injects
an actual SSL-pinning-bypass script automatically, since that requires an
explicitly chosen target app package and is an active operation out of
scope for an automated recon check.
"""
from __future__ import annotations

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_REQUIRES_HARDWARE,
    tool_result,
)
from nexus.tools.mobile._mobile_common import frida_status
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """mobile tool: cert pinning bypass — requires-device honest degrade,
    with a real read-only Frida USB-device check when available."""
    status_info = frida_status()

    if not status_info["frida_python_installed"]:
        return tool_result(
            "mobile.cert_pinning_bypass", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Certificate-pinning bypass testing against {target} requires the `frida` Python "
                    f"package plus a real attached device/emulator — neither is available here",
            error="requires_hardware: frida not installed",
            metadata=status_info,
        )

    if not status_info["device_attached"]:
        return tool_result(
            "mobile.cert_pinning_bypass", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"Certificate-pinning bypass testing against {target} requires a real attached "
                    f"device/emulator reachable via frida.get_usb_device() — none is currently attached",
            error="requires_hardware: no USB device reachable via frida",
            metadata=status_info,
        )

    # frida is installed AND a real device is genuinely attached — report
    # that honestly, but do not auto-inject a bypass script: that requires
    # an explicitly chosen target app package (an active operation, not a
    # safe automated recon check).
    findings = [Finding(
        title="Frida-reachable device detected — pinning bypass requires explicit target app selection",
        severity="info",
        confidence="certain",
        affected_asset=target,
        evidence=f"device_id={status_info['device_id']!r}, device_name={status_info['device_name']!r}",
        remediation="Select the specific installed app package to attach to, then run an explicit, "
                    "human-reviewed Frida SSL-pinning-bypass script against it — not performed "
                    "automatically by this recon check.",
        tool="mobile.cert_pinning_bypass",
    )]
    return tool_result(
        "mobile.cert_pinning_bypass", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Frida device detected ({status_info['device_name']}); automated bypass injection "
                f"not performed without an explicit target app package",
        metadata=status_info,
    )


# Register with tool registry
tool_registry.register("mobile.cert_pinning_bypass", run, metadata={
    "name": "mobile.cert_pinning_bypass",
    "domain": "mobile",
    "status": "requires_hardware",
    "description": "Certificate-pinning bypass testing — requires frida + a real attached "
                    "device/emulator; performs a real read-only device check, never a fabricated result",
    "parameters": {
        "target": "Target app identifier or domain being tested for pinning bypass",
    },
})
