#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Android Analysis
Domain: mobile

Android app security analysis is inherently FILE-based — it requires a real
local .apk archive to inspect. This previously ignored `target` entirely and
reported a DNS resolve + bare HTTP GET on `/` as if it were an Android
security assessment — always with status "completed" — caught during an
audit alongside hardware.usb_attacks. It now does REAL zipfile-based
analysis of the archive (permissions, debuggable flag, network security
config, native libs), preferring androguard for authoritative manifest
parsing when installed, and honestly degrades (STATUS_OUT_OF_SCOPE /
STATUS_FAILED) when `target` isn't a real, valid local .apk file.
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
    """mobile tool: Android security analysis of a local .apk — permissions,
    debuggable flag, network security config, native libs."""
    if not isinstance(target, str) or not target.lower().endswith(".apk"):
        return tool_result(
            "mobile.android_analysis", target,
            status=STATUS_OUT_OF_SCOPE,
            summary="Android analysis requires a local .apk file path as the target",
            error="out_of_scope: target does not look like a .apk file path",
        )
    if not is_apk_target(target):
        return tool_result(
            "mobile.android_analysis", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"No such local .apk file: {target}",
            error="out_of_scope: target .apk path does not exist on this filesystem",
        )

    info = parse_apk(target)
    if not info["valid"]:
        return tool_result(
            "mobile.android_analysis", target,
            status=STATUS_FAILED,
            summary=f"Failed to open {target} as a ZIP/APK archive",
            error=info["error"],
        )

    findings: list[Finding] = []

    debuggable = info["debuggable"]
    if debuggable:
        findings.append(Finding(
            title="Application is debuggable",
            severity="high",
            confidence="high" if info["androguard_used"] else "low",
            affected_asset=target,
            evidence=f"android:debuggable indicator detected "
                     f"({'androguard' if info['androguard_used'] else 'heuristic byte scan'})",
            remediation="Set android:debuggable=\"false\" (or omit it) in release builds.",
            references=["CWE-489"],
            tool="mobile.android_analysis",
        ))

    if not info["has_network_security_config"]:
        findings.append(Finding(
            title="No Network Security Config detected",
            severity="medium",
            confidence="low",
            affected_asset=target,
            evidence="No res/xml entry containing 'network_security_config' was found in the archive.",
            remediation="Add a Network Security Configuration to restrict cleartext traffic and pin certificates.",
            references=["OWASP-MASVS-NETWORK"],
            tool="mobile.android_analysis",
        ))
    else:
        findings.append(Finding(
            title="Network Security Config present",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence="An entry containing 'network_security_config' was found in the archive.",
            remediation="",
            tool="mobile.android_analysis",
        ))

    if info["androguard_used"]:
        dangerous = [p for p in info["permissions"] if any(
            k in p for k in ("SEND_SMS", "RECEIVE_SMS", "READ_SMS", "CALL_PHONE",
                              "READ_CONTACTS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION")
        )]
        if dangerous:
            findings.append(Finding(
                title=f"Sensitive permissions requested ({len(dangerous)})",
                severity="medium",
                confidence="high",
                affected_asset=target,
                evidence=", ".join(dangerous),
                remediation="Confirm each sensitive permission is justified by an in-app feature; "
                            "apply least privilege.",
                references=["OWASP-MASVS-PLATFORM"],
                tool="mobile.android_analysis",
            ))
    elif info["manifest_string_hits"]:
        findings.append(Finding(
            title="Manifest heuristic indicators (androguard unavailable)",
            severity="info",
            confidence="low",
            affected_asset=target,
            evidence=f"Best-effort byte-level search matched: {info['manifest_string_hits']}",
            remediation="Install androguard for authoritative permission/manifest parsing.",
            tool="mobile.android_analysis",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "mobile.android_analysis", target,
        status=status,
        findings=findings,
        summary=f"Analyzed {target}: entries={info['entry_count']}, "
                f"debuggable={debuggable}, network_security_config={info['has_network_security_config']}, "
                f"androguard_used={info['androguard_used']}",
        metadata=info,
    )


# Register with tool registry
tool_registry.register("mobile.android_analysis", run, metadata={
    "name": "mobile.android_analysis",
    "domain": "mobile",
    "status": "completed",
    "description": "Real zipfile/androguard-based Android APK security analysis "
                    "(debuggable flag, network security config, sensitive permissions)",
    "parameters": {
        "target": "Local path to a .apk file",
    },
})
