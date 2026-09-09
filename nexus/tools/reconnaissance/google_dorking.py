#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.google_dorking
Domain: reconnaissance

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to Google dorking at all).
Caught during a follow-up audit. Automating real Google scraping violates
Google's Terms of Service and is unreliable (CAPTCHAs, rate limits) — the
honest, correct behavior is to generate a real, curated set of actionable
Google dork query strings tailored to the target, clearly labeled as
queries for the operator to run manually, not fabricated "results".
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry

_TOOL_NAME = "reconnaissance.google_dorking"

_DORK_CATEGORIES: dict[str, list[str]] = {
    "exposed documents": [
        "site:{d} filetype:pdf", "site:{d} filetype:doc OR filetype:docx",
        "site:{d} filetype:xls OR filetype:xlsx",
    ],
    "login/admin panels": [
        "site:{d} inurl:admin", "site:{d} inurl:login", "site:{d} intitle:\"admin panel\"",
    ],
    "exposed config/backup files": [
        "site:{d} ext:env OR ext:config OR ext:bak", "site:{d} inurl:wp-config.php",
        "site:{d} ext:sql", "site:{d} filetype:log",
    ],
    "error messages / stack traces": [
        "site:{d} intext:\"sql syntax\"", "site:{d} intext:\"stack trace\"",
        "site:{d} intext:\"warning: mysql\"",
    ],
    "exposed directories": [
        "site:{d} intitle:\"index of /\"", "site:{d} intitle:\"index of /backup\"",
    ],
    "subdomains and related sites": [
        "site:*.{d} -site:www.{d}",
    ],
}


def run(target: str, **kwargs: Any) -> dict:
    """Generate real, actionable Google dork queries for the target — for manual execution."""
    domain = target.strip().lower()
    if not domain:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    all_queries: dict[str, list[str]] = {}
    for category, templates in _DORK_CATEGORIES.items():
        queries = [t.format(d=domain) for t in templates]
        all_queries[category] = queries
        findings.append(Finding(
            title=f"Google dork queries generated: {category}",
            severity="info",
            confidence="certain",
            affected_asset=domain,
            evidence="Run these manually in a browser (automated scraping of Google violates its ToS "
                     f"and is unreliable): {queries}",
            remediation="Manually review any results these queries return for unintended public exposure.",
            tool=_TOOL_NAME,
            references=["MITRE ATT&CK T1593"],
        ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Generated {sum(len(v) for v in all_queries.values())} Google dork queries across "
                f"{len(all_queries)} categories for {domain} — for manual execution only",
        metadata={"dork_queries": all_queries},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Generates real, actionable Google dork query strings tailored to the target domain "
                    "for manual execution (does not scrape Google, which would violate its ToS)",
    "parameters": {"target": "Target domain to generate dork queries for"},
})
