#!/usr/bin/env python3
"""
NEXUS-STRIKE — threat_intel tool: TI IOC Collection
Domain: threat_intel

Real IOC intake: classifies the indicator's type (IP / domain / hash) and
records a collection entry, then attempts a real, immediate triage check —
Spamhaus ZEN DNSBL for IPs (free, no key), VirusTotal/OTX for domains and
hashes if a key is configured. When no key is configured for a
domain/hash, the collection entry is still recorded (that part is honest
and real — the indicator genuinely was classified and logged) but the
enrichment/verdict field is explicitly marked unavailable rather than
fabricated.

This was previously one of 8 threat_intel tools sharing byte-for-byte
identical fake logic (DNS resolve + bare HTTP GET on `/`, unrelated to IOC
collection) — caught during this session's audit.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
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

_TOOL_NAME = "threat_intel.ti_ioc_collection"


def run(target: str, **kwargs: Any) -> dict:
    """Classify and collect a single IOC, with a real best-effort triage check."""
    kind = classify_target(target)
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record: dict[str, Any] = {
        "ioc": target,
        "type": kind,
        "collected_at": collected_at,
        "verdict": "unenriched",
        "sources_checked": [],
    }

    if kind == "ip":
        dnsbl = dnsbl_lookup(target)
        if dnsbl.get("error"):
            return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=dnsbl["error"],
                                metadata={"record": record})
        record["sources_checked"].append("spamhaus_zen_dnsbl")
        record["dnsbl"] = dnsbl
        record["verdict"] = "malicious" if dnsbl.get("listed") else "clean"

        finding = Finding(
            title=f"IOC collected: {target} ({kind})",
            severity="high" if dnsbl.get("listed") else "info",
            confidence="certain",
            affected_asset=target,
            evidence=f"Collected {kind} IOC {target}; Spamhaus ZEN verdict: {record['verdict']}"
                     + (f" ({dnsbl.get('reason')})" if dnsbl.get("listed") else ""),
            tool=_TOOL_NAME,
        )
        return tool_result(
            _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
            summary=f"Collected IOC {target} (type={kind}, verdict={record['verdict']})",
            metadata={"record": record},
        )

    key_info = get_api_key("VIRUSTOTAL_API_KEY", "OTX_API_KEY")
    if not key_info:
        record["verdict"] = "unenriched"
        record["note"] = "no VIRUSTOTAL_API_KEY/OTX_API_KEY configured — indicator classified and " \
                          "logged for real, but no free feed exists to enrich a domain/hash without a key"
        finding = Finding(
            title=f"IOC collected (unenriched): {target} ({kind})",
            severity="info",
            confidence="certain",
            affected_asset=target,
            evidence=f"Collected {kind} IOC {target}; classification is real, but enrichment was not "
                     f"attempted — no API key configured for a {kind} lookup",
            tool=_TOOL_NAME,
        )
        return tool_result(
            _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
            summary=f"Collected IOC {target} (type={kind}); classification real, enrichment "
                    f"unavailable without VIRUSTOTAL_API_KEY/OTX_API_KEY",
            metadata={"record": record},
        )

    try:
        source, data = query_keyed_feed(target, kind, key_info)
    except FeedHTTPError as exc:
        record["note"] = f"{key_info[0]} lookup failed: HTTP {exc.code} {exc.reason}"
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"IOC collection triage lookup failed: HTTP {exc.code} {exc.reason}",
                            metadata={"record": record})
    except Exception as exc:  # noqa: BLE001 - network/JSON failures surfaced honestly
        record["note"] = f"lookup failed: {exc}"
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"IOC collection triage lookup failed: {exc}", metadata={"record": record})

    record["sources_checked"].append(source.lower())
    record["verdict"] = "enriched"
    record["raw"] = data
    finding = Finding(
        title=f"IOC collected and enriched via {source}: {target} ({kind})",
        severity="medium",
        confidence="high",
        affected_asset=target,
        evidence=f"Collected {kind} IOC {target}; real {source} data attached",
        tool=_TOOL_NAME,
    )
    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
        summary=f"Collected and enriched IOC {target} via {source} (type={kind})",
        metadata={"record": record},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "threat_intel",
    "status": "completed",
    "description": "Real IOC classification + collection record, with a best-effort real triage check "
                    "(Spamhaus ZEN DNSBL for IPs, VirusTotal/OTX for domains/hashes if a key is set)",
    "parameters": {
        "target": "IP address, domain, or file hash (MD5/SHA1/SHA256) to collect",
    },
})
