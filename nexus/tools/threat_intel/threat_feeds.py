#!/usr/bin/env python3
"""
NEXUS-STRIKE — threat_intel tool: Threat Feeds
Domain: threat_intel

Real threat-feed correlation. An IP target gets a genuine, free, no-key
Spamhaus ZEN DNSBL lookup (a real spam/abuse blocklist feed). A domain or
file-hash target gets a real VirusTotal/OTX API call IF an API key is
configured (VIRUSTOTAL_API_KEY / OTX_API_KEY) — otherwise this honestly
reports that no free feed covers that indicator type rather than
fabricating IOC data.

This was previously one of 8 threat_intel tools sharing byte-for-byte
identical fake logic (DNS resolve + bare HTTP GET on `/`, unrelated to
threat feeds at all, always reporting "completed") — caught during this
session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_REQUIRES_CREDENTIALS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.threat_intel._common import (
    FeedHTTPError,
    classify_target,
    dnsbl_lookup,
    get_api_key,
    query_keyed_feed,
)

_TOOL_NAME = "threat_intel.threat_feeds"


def run(target: str, **kwargs: Any) -> dict:
    """Real threat feed correlation for an IP, domain, or hash indicator."""
    kind = classify_target(target)

    if kind == "ip":
        result = dnsbl_lookup(target)
        if result.get("error"):
            return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=result["error"])

        if result["listed"]:
            finding = Finding(
                title=f"{target} listed on Spamhaus ZEN DNSBL",
                severity="high",
                confidence="certain",
                affected_asset=target,
                evidence=f"Real DNSBL query for {result['query']} resolved to {result['return_code']} "
                         f"({result['reason']})",
                remediation="Investigate this IP for abuse/compromise; consider blocking traffic to/from "
                            "it pending review.",
                tool=_TOOL_NAME,
                references=["https://www.spamhaus.org/zen/"],
            )
            return tool_result(
                _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
                summary=f"{target} IS listed on Spamhaus ZEN ({result['reason']})",
                metadata={"dnsbl": result},
            )

        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"{target} is not listed on Spamhaus ZEN DNSBL (real lookup performed, clean result)",
            metadata={"dnsbl": result},
        )

    # domain or hash — no free no-key feed exists for these, needs a real key
    key_info = get_api_key("VIRUSTOTAL_API_KEY", "OTX_API_KEY")
    if not key_info:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_REQUIRES_CREDENTIALS,
            summary=f"No anonymous/no-key threat feed covers {kind} indicators for {target!r}. "
                    "VirusTotal and AlienVault OTX both offer FREE API keys (no payment method, "
                    "no cost) that unlock real domain/hash feed lookups here.",
            error="requires_credentials: set VIRUSTOTAL_API_KEY or OTX_API_KEY (both free to obtain) "
                  "to enable real domain/hash feed lookups; neither was found in the environment",
        )

    try:
        source, data = query_keyed_feed(target, kind, key_info)
    except FeedHTTPError as exc:
        if exc.code in (401, 403):
            return tool_result(_TOOL_NAME, target, status=STATUS_REQUIRES_CREDENTIALS,
                                error=f"{key_info[0]} was rejected by the feed API (HTTP {exc.code})")
        if exc.code == 429:
            return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                                error=f"Feed API rate-limited this request (HTTP 429): {exc.reason}")
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"Feed API returned HTTP {exc.code}: {exc.reason}")
    except Exception as exc:  # noqa: BLE001 - network/JSON failures surfaced honestly
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"Feed API request failed: {exc}")

    finding = Finding(
        title=f"{source} feed result for {target}",
        severity="medium",
        confidence="high",
        affected_asset=target,
        evidence=f"Real {source} API response received for {target} ({kind})",
        tool=_TOOL_NAME,
        references=[f"https://www.virustotal.com/gui/{'domain' if kind == 'domain' else 'file'}/{target}"]
        if source == "VirusTotal" else [f"https://otx.alienvault.com/indicator/{kind}/{target}"],
    )
    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
        summary=f"Real {source} feed lookup completed for {target}",
        metadata={"source": source, "raw": data},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "threat_intel",
    "status": "completed",
    "description": "Real threat feed correlation — Spamhaus ZEN DNSBL for IPs (free, no key), "
                    "VirusTotal/OTX for domains/hashes (requires an API key)",
    "parameters": {
        "target": "IP address, domain, or file hash (MD5/SHA1/SHA256) to check",
    },
})
