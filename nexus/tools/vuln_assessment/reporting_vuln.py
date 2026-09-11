#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Reporting Vuln
Domain: vuln_assessment

Real aggregation/formatting of already-produced findings into a
vuln-report-shaped structure — grouped by severity, with real counts. This
tool does not scan anything itself; it consumes findings= (typically the
merged output of network_vuln_scanning/web_vuln_scanning/cve_analysis/etc.
in a pipeline) and turns them into a report. Given no findings, it
honestly reports there is nothing to report on, rather than fabricating
scan activity against `target` the way the old stub did.

This was previously one of 8 vuln_assessment tools sharing byte-for-byte
identical fake logic (a hardcoded-port TCP scan + bare HTTP GET, unrelated
to reporting) — caught during this session's audit.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result
from nexus.tools.registry import tool_registry

_TOOL_NAME = "vuln_assessment.reporting_vuln"


def run(target: str, **kwargs: Any) -> dict:
    """Real grouping/counting of supplied findings into a report structure."""
    raw_findings = kwargs.get("findings")
    if not isinstance(raw_findings, list) or not raw_findings:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary="No findings were supplied to report on — pass findings=[...] (e.g. the merged "
                    "output of other vuln_assessment tools)",
        )

    normalised = []
    for f in raw_findings:
        normalised.append(f if isinstance(f, dict) else {"title": str(f), "severity": "info"})

    by_severity: dict[str, list[dict]] = {}
    for f in normalised:
        sev = str(f.get("severity", "info")).lower()
        if sev not in Finding.SEVERITY_ORDER:
            sev = "info"
        by_severity.setdefault(sev, []).append(f)

    counts = {sev: len(by_severity.get(sev, [])) for sev in Finding.SEVERITY_ORDER}
    total = sum(counts.values())
    by_tool = Counter(str(f.get("tool", "unknown")) for f in normalised)

    summary = (
        f"Vulnerability report for {target}: {total} finding(s) — "
        + ", ".join(f"{sev}:{counts[sev]}" for sev in Finding.SEVERITY_ORDER if counts[sev])
    )

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[], summary=summary,
        metadata={
            "severity_counts": counts,
            "total_findings": total,
            "findings_by_severity": by_severity,
            "findings_by_tool": dict(by_tool),
        },
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "Real aggregation/formatting of supplied findings into a grouped-by-severity "
                    "vuln report with real counts",
    "parameters": {
        "target": "Report subject label",
        "findings": "Required: list of finding dicts to group/count",
    },
})
