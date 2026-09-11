#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Ios Analysis
Domain: mobile

iOS app security analysis is inherently FILE-based — it requires a real
local .ipa archive to inspect. This previously ignored `target` entirely
and reported a DNS resolve + bare HTTP GET on `/` as if it were an iOS
security assessment — always with status "completed" — caught during an
audit alongside hardware.usb_attacks. It now does REAL zipfile-based
extraction (IPAs are ZIP files) and stdlib `plistlib` parsing of
Info.plist, flagging security-relevant configuration (App Transport
Security exceptions, exported/queryable URL schemes, background modes),
honestly degrading (STATUS_OUT_OF_SCOPE / STATUS_FAILED) when `target`
isn't a real, valid local .ipa file.
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
from nexus.tools.mobile._mobile_common import is_ipa_target, parse_ipa
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """mobile tool: iOS security analysis of a local .ipa — App Transport
    Security config, URL scheme exposure, background modes."""
    if not isinstance(target, str) or not target.lower().endswith(".ipa"):
        return tool_result(
            "mobile.ios_analysis", target,
            status=STATUS_OUT_OF_SCOPE,
            summary="iOS analysis requires a local .ipa file path as the target",
            error="out_of_scope: target does not look like a .ipa file path",
        )
    if not is_ipa_target(target):
        return tool_result(
            "mobile.ios_analysis", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"No such local .ipa file: {target}",
            error="out_of_scope: target .ipa path does not exist on this filesystem",
        )

    info = parse_ipa(target)
    if not info["valid"] or not info["info_plist_path"]:
        return tool_result(
            "mobile.ios_analysis", target,
            status=STATUS_FAILED,
            summary=f"Failed to open/parse {target} as an IPA bundle",
            error=info["error"],
            metadata=info,
        )

    findings: list[Finding] = []
    plist = info["info_plist"]

    if info["ats_arbitrary_loads"]:
        findings.append(Finding(
            title="App Transport Security disabled (NSAllowsArbitraryLoads=true)",
            severity="high",
            confidence="certain",
            affected_asset=target,
            evidence="Info.plist NSAppTransportSecurity.NSAllowsArbitraryLoads == true — "
                     "cleartext/unvalidated HTTP connections are permitted app-wide.",
            remediation="Remove NSAllowsArbitraryLoads and use scoped, per-domain ATS exceptions only.",
            references=["CWE-319", "OWASP-MASVS-NETWORK"],
            tool="mobile.ios_analysis",
        ))
    else:
        findings.append(Finding(
            title="App Transport Security not globally disabled",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence="NSAllowsArbitraryLoads not set to true in Info.plist.",
            remediation="",
            tool="mobile.ios_analysis",
        ))

    url_schemes = []
    for entry in plist.get("CFBundleURLTypes", []) or []:
        if isinstance(entry, dict):
            url_schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    if url_schemes:
        findings.append(Finding(
            title=f"Custom URL schemes registered ({len(url_schemes)})",
            severity="low",
            confidence="high",
            affected_asset=target,
            evidence=", ".join(url_schemes),
            remediation="Validate all input received via custom URL scheme handlers; "
                        "avoid using them for sensitive actions without additional authentication.",
            references=["OWASP-MASVS-PLATFORM"],
            tool="mobile.ios_analysis",
        ))

    bg_modes = plist.get("UIBackgroundModes", []) or []
    if bg_modes:
        findings.append(Finding(
            title=f"Background modes declared ({len(bg_modes)})",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence=", ".join(bg_modes),
            remediation="Confirm each background mode (e.g. location/audio/bluetooth) is required "
                        "by an actual feature — unused background modes increase attack surface.",
            tool="mobile.ios_analysis",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "mobile.ios_analysis", target,
        status=status,
        findings=findings,
        summary=f"Analyzed {target}: bundle_id={info['bundle_id']}, "
                f"ats_arbitrary_loads={info['ats_arbitrary_loads']}, url_schemes={len(url_schemes)}",
        metadata=info,
    )


# Register with tool registry
tool_registry.register("mobile.ios_analysis", run, metadata={
    "name": "mobile.ios_analysis",
    "domain": "mobile",
    "status": "completed",
    "description": "Real zipfile/plistlib-based iOS IPA security analysis "
                    "(App Transport Security, URL scheme exposure, background modes)",
    "parameters": {
        "target": "Local path to a .ipa file",
    },
})
