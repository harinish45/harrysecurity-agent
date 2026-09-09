#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: CVE Analysis
Domain: vuln_assessment

Real query against the free NVD CVE 2.0 API (no API key required for
low-volume use) when `target` looks like a product/version keyword string
(e.g. "Apache 2.4.49", "OpenSSL 1.1.1"). Parses real CVE IDs and CVSS
scores out of the JSON response. When `target` looks like a network host,
IP, or URL instead (not a keyword NVD's search endpoint can use), this
honestly says so rather than searching NVD for a host string and returning
nonsense results. Rate-limiting/blocking (HTTP 403/429) is reported
honestly, not silently swallowed into a fake "completed, 0 findings".

This was previously one of 8 vuln_assessment tools sharing byte-for-byte
identical fake logic (a hardcoded-port TCP scan + bare HTTP GET, unrelated
to CVE data) — caught during this session's audit.
"""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "vuln_assessment.cve_analysis"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def _looks_like_product_keyword(target: str) -> bool:
    """True when `target` looks like an NVD keyword search string
    (a product/version name) rather than a network host/IP/URL."""
    t = target.strip()
    if not t or _URL_SCHEME_RE.match(t):
        return False
    host_candidate = t.split(":", 1)[0].split("/", 1)[0]
    try:
        ipaddress.ip_address(host_candidate)
        return False
    except ValueError:
        pass
    if ":" in t and t.rsplit(":", 1)[1].isdigit():
        return False  # host:port shape
    return True


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def run(target: str, **kwargs: Any) -> dict:
    """Real NVD CVE keyword search."""
    if not _looks_like_product_keyword(target):
        return tool_result(
            _TOOL_NAME, target, status=STATUS_OUT_OF_SCOPE,
            summary=f"{target!r} looks like a network host/IP/URL, not a product/version keyword — "
                    f"NVD's search API takes a product string (e.g. target='Apache 2.4.49')",
            error="out_of_scope: pass a product/version keyword as target, or use "
                  "vuln_assessment.network_vuln_scanning / web_vuln_scanning for host-based scanning",
        )

    results_per_page = int(kwargs.get("results_per_page", 20) or 20)
    max_results = int(kwargs.get("max_results", 20) or 20)
    query = urllib.parse.urlencode({"keywordSearch": target, "resultsPerPage": results_per_page})
    url = f"{_NVD_URL}?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0 (+security-assessment)"})

    try:
        with safe_urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            return tool_result(
                _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
                summary=f"NVD rate-limited/blocked this request (HTTP {exc.code}) — unauthenticated "
                        f"NVD API access is capped at roughly 5 requests/30s",
                error=f"NVD API returned HTTP {exc.code}: {exc.reason}",
            )
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"NVD API returned HTTP {exc.code}: {exc.reason}")
    except Exception as exc:  # noqa: BLE001 - network/JSON failures surfaced honestly
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"NVD API request failed: {exc}")

    vulns = payload.get("vulnerabilities", []) or []
    if not vulns:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"NVD returned 0 CVEs for keyword {target!r}",
            metadata={"total_results": payload.get("totalResults", 0)},
        )

    findings: list[Finding] = []
    for item in vulns[:max_results]:
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id", "unknown")
        descriptions = cve.get("descriptions", []) or []
        desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

        base_score = None
        base_severity = None
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {}) or {}
                base_score = cvss_data.get("baseScore")
                base_severity = (entries[0].get("baseSeverity") or cvss_data.get("baseSeverity") or "").lower()
                break

        severity = base_severity if base_severity in Finding.SEVERITY_ORDER else _severity_from_score(base_score)
        references = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
        references += [r.get("url") for r in (cve.get("references") or [])[:3] if r.get("url")]

        findings.append(Finding(
            title=f"{cve_id}: {desc[:100]}" if desc else cve_id,
            severity=severity,
            confidence="certain",
            affected_asset=target,
            evidence=f"NVD CVE {cve_id} — CVSS base score "
                     f"{base_score if base_score is not None else 'n/a'} ({base_severity or 'unrated'}). "
                     f"{desc[:300]}",
            remediation="Review vendor advisories for this CVE and apply the relevant patch/mitigation.",
            references=references,
            tool=_TOOL_NAME,
        ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"NVD returned {len(vulns)} CVE(s) for keyword {target!r} ({len(findings)} shown)",
        metadata={"total_results": payload.get("totalResults"), "keyword": target},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "Real NVD CVE 2.0 API keyword search — parses genuine CVE IDs/CVSS scores; "
                    "honestly out-of-scope for host/IP/URL targets",
    "parameters": {
        "target": "Product/version keyword to search NVD for (e.g. 'Apache 2.4.49')",
        "results_per_page": "NVD resultsPerPage (default 20)",
        "max_results": "Max findings to build (default 20)",
    },
})
