#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Apk Decompilation
Domain: mobile

APK decompilation is inherently FILE-based — it requires a real local .apk
archive. This previously ignored `target` entirely and reported a DNS
resolve + bare HTTP GET on `/` as if it were APK analysis — always with
status "completed" — caught during an audit alongside hardware.usb_attacks.
It now does REAL zipfile-based extraction of the archive (APKs are ZIP
files) and reports which decompiled artifacts are actually present,
honestly degrading (STATUS_OUT_OF_SCOPE / STATUS_FAILED) when `target`
isn't a real, valid local .apk file.
"""
from __future__ import annotations

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.mobile._mobile_common import is_apk_target, parse_apk
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """mobile tool: APK decompilation — real zipfile-based extraction/listing
    of a local .apk archive, with best-effort manifest inspection."""
    if not isinstance(target, str) or not target.lower().endswith(".apk"):
        return tool_result(
            "mobile.apk_decompilation", target,
            status=STATUS_OUT_OF_SCOPE,
            summary="APK decompilation requires a local .apk file path as the target",
            error="out_of_scope: target does not look like a .apk file path",
        )
    if not is_apk_target(target):
        return tool_result(
            "mobile.apk_decompilation", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"No such local .apk file: {target}",
            error="out_of_scope: target .apk path does not exist on this filesystem",
        )

    info = parse_apk(target)
    if not info["valid"]:
        return tool_result(
            "mobile.apk_decompilation", target,
            status=STATUS_FAILED,
            summary=f"Failed to open {target} as a ZIP/APK archive",
            error=info["error"],
        )

    findings: list[Finding] = []
    findings.append(Finding(
        title=f"APK archive extracted: {info['entry_count']} entries",
        severity="info",
        confidence="certain",
        affected_asset=target,
        evidence=f"classes.dex present={info['has_classes_dex']}, "
                 f"AndroidManifest.xml present={info['has_manifest']}, "
                 f"native libraries={len(info['native_libs'])}",
        remediation="Informational — confirms the archive decompiled/extracted successfully.",
        tool="mobile.apk_decompilation",
    ))
    if not info["has_classes_dex"]:
        findings.append(Finding(
            title="No classes.dex found in APK",
            severity="low",
            confidence="high",
            affected_asset=target,
            evidence="Archive did not contain a classes.dex (or classesN.dex) entry — "
                     "unusual for a standard installable APK.",
            remediation="Verify this is a genuine, complete APK rather than a partial/split bundle.",
            tool="mobile.apk_decompilation",
        ))
    if info["native_libs"]:
        findings.append(Finding(
            title=f"Native libraries present ({len(info['native_libs'])})",
            severity="info",
            confidence="certain",
            affected_asset=target,
            evidence=", ".join(info["native_libs"][:10]) + ("..." if len(info["native_libs"]) > 10 else ""),
            remediation="Native (.so) libraries should be reverse engineered separately (objdump/Ghidra) "
                        "for a full security review — not performed by this static archive listing.",
            tool="mobile.apk_decompilation",
        ))
    if info["androguard_used"]:
        findings.append(Finding(
            title="Manifest parsed via androguard",
            severity="info",
            confidence="certain",
            affected_asset=target,
            evidence=f"package={info['package_name']!r}, min_sdk={info['min_sdk']!r}, "
                     f"debuggable={info['debuggable']}, permissions={len(info['permissions'])}",
            remediation="",
            tool="mobile.apk_decompilation",
        ))
    elif info["manifest_string_hits"]:
        findings.append(Finding(
            title="Manifest heuristic string matches (androguard unavailable)",
            severity="info",
            confidence="low",
            affected_asset=target,
            evidence=f"Best-effort byte-level search matched: {info['manifest_string_hits']} "
                     f"(no structured XML parse — androguard not installed)",
            remediation="Install androguard for authoritative AndroidManifest.xml parsing.",
            tool="mobile.apk_decompilation",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "mobile.apk_decompilation", target,
        status=status,
        findings=findings,
        summary=f"Extracted {info['entry_count']} entries from {target}; "
                f"classes.dex={info['has_classes_dex']}, native_libs={len(info['native_libs'])}, "
                f"androguard_used={info['androguard_used']}",
        metadata=info,
    )


# Register with tool registry
tool_registry.register("mobile.apk_decompilation", run, metadata={
    "name": "mobile.apk_decompilation",
    "domain": "mobile",
    "status": "completed",
    "description": "Real zipfile-based APK extraction/decompilation-artifact listing "
                    "(classes.dex, manifest, native libs), with androguard manifest parsing when available",
    "parameters": {
        "target": "Local path to a .apk file",
    },
})
