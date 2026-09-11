#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Root Jailbreak Detection
Domain: mobile

Root/jailbreak detection fundamentally requires a real attached device —
there's no network-observable substitute the way HTTP/TLS/DNS-based tools
have one. This previously ignored `target` entirely and reported a DNS
resolve + bare HTTP GET on `/` as if it were device root/jailbreak
detection — always with status "completed" — caught during an audit
alongside hardware.usb_attacks. It now honestly reports
STATUS_REQUIRES_HARDWARE unless `adb` (Android) or `idevice_id`
(libimobiledevice, iOS) is installed AND a real device is actually
connected, in which case it runs a real, minimal, safe (read-only) check
for well-known root/jailbreak indicators.
"""
from __future__ import annotations

import subprocess

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_REQUIRES_HARDWARE,
    tool_result,
)
from nexus.tools.mobile._mobile_common import adb_status, idevice_status
from nexus.tools.registry import tool_registry

# Real, minimal, safe (read-only) adb shell commands used to look for
# well-known root indicators. No modification of device state.
_ADB_ROOT_CHECKS = [
    ("which su", "su binary present on PATH"),
    ("getprop ro.build.tags", "build tags (test-keys indicates a custom/rooted build)"),
]


def _android_check(target: str, status_info: dict) -> dict:
    evidence_lines = []
    root_indicators = []
    for cmd, description in _ADB_ROOT_CHECKS:
        try:
            proc = subprocess.run(
                ["adb", "shell", cmd], capture_output=True, text=True, timeout=10
            )
            out = proc.stdout.strip()
            evidence_lines.append(f"`adb shell {cmd}` -> {out!r} ({description})")
            if cmd.startswith("which su") and out and "not found" not in out.lower():
                root_indicators.append("su binary present")
            if cmd.startswith("getprop ro.build.tags") and "test-keys" in out.lower():
                root_indicators.append("build tagged test-keys")
        except Exception as e:
            evidence_lines.append(f"`adb shell {cmd}` failed: {e}")

    findings = []
    if root_indicators:
        findings.append(Finding(
            title="Root indicator(s) detected on connected Android device",
            severity="high",
            confidence="high",
            affected_asset=target,
            evidence="; ".join(evidence_lines),
            remediation="A rooted device should not be used to process sensitive data for this app; "
                        "if this is intentional test hardware, disregard.",
            references=["OWASP-MASVS-RESILIENCE"],
            tool="mobile.root_jailbreak_detection",
        ))
    else:
        findings.append(Finding(
            title="No root indicators detected on connected Android device",
            severity="info",
            confidence="medium",
            affected_asset=target,
            evidence="; ".join(evidence_lines),
            remediation="",
            tool="mobile.root_jailbreak_detection",
        ))
    status = STATUS_COMPLETED if root_indicators else STATUS_NO_FINDINGS
    return tool_result(
        "mobile.root_jailbreak_detection", target,
        status=status,
        findings=findings,
        summary=f"Checked connected Android device ({status_info['devices'][0]}) for root indicators: "
                f"{'FOUND' if root_indicators else 'none found'}",
        metadata={**status_info, "checks": evidence_lines},
    )


def run(target: str, **kwargs) -> dict:
    """mobile tool: root/jailbreak detection — requires-device honest
    degrade, with a real minimal safe check when a device is connected."""
    adb_info = adb_status()
    idevice_info = idevice_status()

    if adb_info["device_connected"]:
        return _android_check(target, adb_info)

    if idevice_info["device_connected"]:
        findings = [Finding(
            title="Paired iOS device detected — jailbreak indicators not auto-checked",
            severity="info",
            confidence="medium",
            affected_asset=target,
            evidence=f"idevice_id -l reported UDID(s): {idevice_info['devices']}",
            remediation="Run a dedicated jailbreak-detection check (e.g. via `ideviceinstaller`/SSH to "
                        "look for Cydia/Sileo, resigned system binaries) — not performed automatically "
                        "here since it requires deeper device access than a UDID listing.",
            tool="mobile.root_jailbreak_detection",
        )]
        return tool_result(
            "mobile.root_jailbreak_detection", target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Paired iOS device detected ({idevice_info['devices'][0]}); "
                    f"jailbreak indicator check requires deeper device access than available here",
            metadata=idevice_info,
        )

    return tool_result(
        "mobile.root_jailbreak_detection", target,
        status=STATUS_REQUIRES_HARDWARE,
        summary=f"Root/jailbreak detection for {target} requires a real connected device — "
                f"adb: {adb_info['error'] or 'no device'}; idevice_id: {idevice_info['error'] or 'no device'}",
        error="requires_hardware: no adb-connected Android device or paired iOS device found",
        metadata={"adb": adb_info, "idevice": idevice_info},
    )


# Register with tool registry
tool_registry.register("mobile.root_jailbreak_detection", run, metadata={
    "name": "mobile.root_jailbreak_detection",
    "domain": "mobile",
    "status": "requires_hardware",
    "description": "Root/jailbreak detection — requires a real connected device via adb or "
                    "libimobiledevice; performs a real minimal safe check, never a fabricated result",
    "parameters": {
        "target": "Target device/app identifier",
    },
})
