#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Ipa Analysis
Domain: mobile

IPA decompilation/extraction is inherently FILE-based — it requires a real
local .ipa archive. This previously ignored `target` entirely and reported a
DNS resolve + bare HTTP GET on `/` as if it were IPA analysis — always with
status "completed" — caught during an audit alongside hardware.usb_attacks.
It now does REAL zipfile-based extraction (IPAs are ZIP files, with
Payload/<AppName>.app/Info.plist as the app bundle manifest) and parses that
Info.plist with stdlib `plistlib`, honestly degrading (STATUS_OUT_OF_SCOPE /
STATUS_FAILED) when `target` isn't a real, valid local .ipa file.
"""
from __future__ import annotations

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.mobile._mobile_common import is_ipa_target, parse_ipa
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """mobile tool: IPA extraction — real zipfile-based listing of a local
    .ipa archive plus stdlib plistlib parsing of its Info.plist."""
    if not isinstance(target, str) or not target.lower().endswith(".ipa"):
        return tool_result(
            "mobile.ipa_analysis", target,
            status=STATUS_OUT_OF_SCOPE,
            summary="IPA analysis requires a local .ipa file path as the target",
            error="out_of_scope: target does not look like a .ipa file path",
        )
    if not is_ipa_target(target):
        return tool_result(
            "mobile.ipa_analysis", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"No such local .ipa file: {target}",
            error="out_of_scope: target .ipa path does not exist on this filesystem",
        )

    info = parse_ipa(target)
    if not info["valid"]:
        return tool_result(
            "mobile.ipa_analysis", target,
            status=STATUS_FAILED,
            summary=f"Failed to open {target} as a ZIP/IPA archive",
            error=info["error"],
        )
    if not info["info_plist_path"]:
        return tool_result(
            "mobile.ipa_analysis", target,
            status=STATUS_FAILED,
            summary=f"{target} is a valid ZIP but not a standard IPA bundle",
            error=info["error"],
            metadata=info,
        )

    findings: list[Finding] = [Finding(
        title=f"IPA archive extracted: {info['entry_count']} entries",
        severity="info",
        confidence="certain",
        affected_asset=target,
        evidence=f"Info.plist at {info['info_plist_path']}, bundle_id={info['bundle_id']!r}, "
                 f"bundle_name={info['bundle_name']!r}",
        remediation="Informational — confirms the archive extracted and Info.plist parsed successfully.",
        tool="mobile.ipa_analysis",
    )]

    if info["ats_arbitrary_loads"]:
        findings.append(Finding(
            title="App Transport Security disabled (NSAllowsArbitraryLoads=true)",
            severity="high",
            confidence="certain",
            affected_asset=target,
            evidence="Info.plist NSAppTransportSecurity.NSAllowsArbitraryLoads == true",
            remediation="Remove NSAllowsArbitraryLoads and use per-domain ATS exceptions only where "
                        "strictly required.",
            references=["CWE-319", "OWASP-MASVS-NETWORK"],
            tool="mobile.ipa_analysis",
        ))

    return tool_result(
        "mobile.ipa_analysis", target,
        status=STATUS_COMPLETED,  # extraction + plist parse succeeded — a completed action regardless of findings
        findings=findings,
        summary=f"Extracted {info['entry_count']} entries from {target}; "
                f"bundle_id={info['bundle_id']}, ats_arbitrary_loads={info['ats_arbitrary_loads']}",
        metadata=info,
    )


# Register with tool registry
tool_registry.register("mobile.ipa_analysis", run, metadata={
    "name": "mobile.ipa_analysis",
    "domain": "mobile",
    "status": "completed",
    "description": "Real zipfile-based IPA extraction with stdlib plistlib Info.plist parsing "
                    "(bundle id/name, App Transport Security config)",
    "parameters": {
        "target": "Local path to a .ipa file",
    },
})
