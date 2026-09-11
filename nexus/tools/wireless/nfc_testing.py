#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless tool: Nfc Testing
Domain: wireless

NFC/RFID-proximity testing (reading tag UIDs, probing readers) requires a
local NFC reader physically presented with a tag/card — no network-
observable substitute exists. This previously ran `which <tool>` (a no-op on
Windows) against a hardcoded WiFi-tool binary list unrelated to NFC entirely,
and always reported status "completed" with a canned note — caught during
this session's audit. Now it checks for `nfc-list` (libnfc) on PATH, or
falls back to whether `nfc` (nfcpy) is importable, and:
  - if neither is present, honestly reports STATUS_REQUIRES_HARDWARE;
  - if `nfc-list` is present, it runs a real, read-only reader enumeration
    (lists connected NFC readers, never scans for/reads a tag);
  - if only nfcpy is importable, it attempts to open the default reader —
    failure to open (no reader attached) is honestly reported as
    STATUS_REQUIRES_HARDWARE; results are only ever what was actually
    detected, never fabricated.
"""
from __future__ import annotations

import shutil

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_HARDWARE, tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import run_subprocess, SandboxError


def run(target: str, **kwargs) -> dict:
    """wireless tool: Nfc Testing"""
    nfc_list_path = shutil.which("nfc-list")
    try:
        import nfc as nfcpy
        has_nfcpy = True
    except ImportError:
        nfcpy = None
        has_nfcpy = False

    if not nfc_list_path and not has_nfcpy:
        return tool_result(
            "wireless.nfc_testing", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"NFC assessment of {target} requires a local NFC reader plus either the "
                    f"libnfc `nfc-list` CLI tool or the `nfc` (nfcpy) Python package — neither "
                    f"is present on this host",
            error="requires_hardware: no nfc-list on PATH and nfc (nfcpy) not importable",
            metadata={"nfc_list_path": nfc_list_path, "nfcpy_importable": has_nfcpy},
        )

    if nfc_list_path:
        try:
            result = run_subprocess([nfc_list_path], timeout=10)
            output = result.stdout or ""
        except SandboxError as exc:
            return tool_result(
                "wireless.nfc_testing", target,
                status=STATUS_REQUIRES_HARDWARE,
                summary=f"nfc-list is installed but failed to enumerate NFC readers on this "
                        f"host: {exc}",
                error=str(exc),
            )

        readers = [line.strip() for line in output.splitlines() if line.strip()]
        findings = []
        if readers:
            findings.append(Finding(
                title="NFC reader(s) detected on assessment host",
                severity="info", confidence="high", affected_asset=target,
                evidence="\n".join(readers[:20]),
                remediation="Confirm reader capability before running an authorized NFC/RFID "
                            "test against a target tag/card.",
                tool="wireless.nfc_testing",
            ))
        status = STATUS_COMPLETED if readers else STATUS_NO_FINDINGS
        return tool_result(
            "wireless.nfc_testing", target,
            status=status,
            findings=findings,
            summary=f"nfc-list ran successfully; "
                    f"{'found ' + str(len(readers)) + ' local NFC reader line(s)' if readers else 'no NFC readers enumerated'} "
                    f"on this host. This lists LOCAL reader capability only — it does not "
                    f"assess {target} directly, which requires a physical tag/card presented "
                    f"to the reader.",
            metadata={"raw_output_sample": output[:500]},
        )

    # Only nfcpy is importable — try to actually open the default reader.
    try:
        clf = nfcpy.ContactlessFrontend("usb")
    except Exception as exc:
        return tool_result(
            "wireless.nfc_testing", target,
            status=STATUS_REQUIRES_HARDWARE,
            summary=f"nfcpy is installed but no usable NFC reader was found on this host, so "
                    f"NFC testing of {target} could not be performed",
            error=f"requires_hardware: {exc}",
        )

    try:
        device_info = str(clf.device)
    finally:
        clf.close()

    findings = [Finding(
        title="NFC reader detected via nfcpy",
        severity="info", confidence="high", affected_asset=target,
        evidence=f"device={device_info}",
        remediation="Confirm reader capability before running an authorized NFC/RFID test "
                    "against a target tag/card.",
        tool="wireless.nfc_testing",
    )]
    return tool_result(
        "wireless.nfc_testing", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"nfcpy opened a local NFC reader ({device_info}). This lists LOCAL reader "
                f"capability only — it does not assess {target} directly, which requires a "
                f"physical tag/card presented to the reader.",
        metadata={"device": device_info},
    )


# Register with tool registry
tool_registry.register("wireless.nfc_testing", run, metadata={
    "name": "wireless.nfc_testing",
    "domain": "wireless",
    "status": "requires_hardware",
    "description": "wireless tool: NFC/RFID-proximity testing — checks for `nfc-list` (libnfc) "
                    "on PATH or `nfc` (nfcpy) importable, enumerates/opens a real local reader "
                    "read-only if present, and honestly reports requires_hardware if neither "
                    "is available or no reader is attached",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
