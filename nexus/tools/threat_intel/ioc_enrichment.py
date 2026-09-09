#!/usr/bin/env python3
"""
NEXUS-STRIKE — threat_intel tool: IOC Enrichment
Domain: threat_intel

Real single-indicator enrichment. An IP target gets a genuine Spamhaus
ZEN DNSBL reputation check plus a real reverse-DNS (PTR) lookup for
context. A domain/hash target gets a real VirusTotal/OTX lookup if an API
key is configured, else an honest "no free feed for this indicator type"
degrade — never fabricated reputation/verdict data.

This was previously one of 8 threat_intel tools sharing byte-for-byte
identical fake logic (DNS resolve + bare HTTP GET on `/`, always reporting
"completed" regardless of what was actually checked) — caught during this
session's audit.
"""
from __future__ import annotations

import socket
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
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

_TOOL_NAME = "threat_intel.ioc_enrichment"


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def run(target: str, **kwargs: Any) -> dict:
    """Real enrichment of a single IOC (IP, domain, or hash)."""
    kind = classify_target(target)

    if kind == "ip":
        dnsbl = dnsbl_lookup(target)
        if dnsbl.get("error"):
            return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=dnsbl["error"])
        ptr = _reverse_dns(target)

        evidence_parts = []
        severity = "info"
        if dnsbl.get("listed"):
            severity = "high"
            evidence_parts.append(f"Spamhaus ZEN: LISTED ({dnsbl.get('reason')})")
        else:
            evidence_parts.append("Spamhaus ZEN: not listed")
        evidence_parts.append(f"PTR record: {ptr}" if ptr else "PTR record: none found")

        finding = Finding(
            title=f"IOC enrichment: {target}",
            severity=severity,
            confidence="certain",
            affected_asset=target,
            evidence="; ".join(evidence_parts),
            remediation="Investigate for abuse/compromise; consider blocking." if dnsbl.get("listed") else "",
            tool=_TOOL_NAME,
            references=["https://www.spamhaus.org/zen/"],
        )
        return tool_result(
            _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
            summary=f"Enriched {target}: "
                    f"{'listed on DNSBL' if dnsbl.get('listed') else 'clean on DNSBL'}, PTR={ptr or 'none'}",
            metadata={"dnsbl": dnsbl, "ptr": ptr},
        )

    key_info = get_api_key("VIRUSTOTAL_API_KEY", "OTX_API_KEY")
    if not key_info:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_REQUIRES_CREDENTIALS,
            summary=f"No anonymous/no-key enrichment source covers {kind} indicators for {target!r}. "
                    "VirusTotal and AlienVault OTX both offer FREE API keys (no payment method, "
                    "no cost — sign up at virustotal.com or otx.alienvault.com) that unlock real "
                    "domain/hash enrichment here.",
            error="requires_credentials: set VIRUSTOTAL_API_KEY or OTX_API_KEY (both free to obtain) "
                  "to enable real domain/hash enrichment; neither was found in the environment",
        )

    try:
        source, data = query_keyed_feed(target, kind, key_info)
    except FeedHTTPError as exc:
        if exc.code in (401, 403):
            return tool_result(_TOOL_NAME, target, status=STATUS_REQUIRES_CREDENTIALS,
                                error=f"{key_info[0]} was rejected by the enrichment API (HTTP {exc.code})")
        if exc.code == 429:
            return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                                error=f"Enrichment API rate-limited this request (HTTP 429): {exc.reason}")
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"Enrichment API returned HTTP {exc.code}: {exc.reason}")
    except Exception as exc:  # noqa: BLE001 - network/JSON failures surfaced honestly
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"Enrichment API request failed: {exc}")

    finding = Finding(
        title=f"IOC enrichment via {source}: {target}",
        severity="medium",
        confidence="high",
        affected_asset=target,
        evidence=f"Real {source} enrichment data retrieved for {target} ({kind})",
        tool=_TOOL_NAME,
    )
    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
        summary=f"Real {source} enrichment completed for {target}",
        metadata={"source": source, "raw": data},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "threat_intel",
    "status": "completed",
    "description": "Real single-IOC enrichment — Spamhaus ZEN DNSBL + reverse DNS for IPs (free, no "
                    "key), VirusTotal/OTX for domains/hashes (requires an API key)",
    "parameters": {
        "target": "IP address, domain, or file hash (MD5/SHA1/SHA256) to enrich",
    },
})
