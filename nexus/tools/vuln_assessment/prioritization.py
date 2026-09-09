#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Prioritization
Domain: vuln_assessment

Real prioritization logic combining a severity signal with a genuine
exploit-availability check against CISA's free, public Known Exploited
Vulnerabilities (KEV) catalog (no API key required). A CVE that is
actively known-exploited-in-the-wild is prioritized above any severity
rating alone would suggest — that's real, current threat data, not a
fabricated ranking.

This was previously one of 8 vuln_assessment tools sharing byte-for-byte
identical fake logic (a hardcoded-port TCP scan + bare HTTP GET, unrelated
to prioritization) — caught during this session's audit.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_OUT_OF_SCOPE,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "vuln_assessment.prioritization"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def run(target: str, **kwargs: Any) -> dict:
    """Real KEV-membership-aware prioritization for a CVE."""
    cve_id = kwargs.get("cve_id")
    if not cve_id:
        match = _CVE_RE.search(target or "")
        cve_id = match.group(0).upper() if match else None
    elif cve_id:
        cve_id = str(cve_id).upper()

    severity_hint = str(kwargs.get("severity", "")).strip().lower()
    if severity_hint not in _SEVERITY_RANK:
        severity_hint = ""

    if not cve_id:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_OUT_OF_SCOPE,
            summary="Prioritization needs a CVE ID to check real-world exploitation status",
            error="pass cve_id='CVE-YYYY-NNNNN' (or include one in target) — no CVE ID was found",
        )

    req = urllib.request.Request(_KEV_URL, headers={"User-Agent": "NexusStrike/1.0 (+security-assessment)"})
    try:
        with safe_urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE,
                                summary=f"CISA KEV feed rate-limited/blocked this request (HTTP {exc.code})",
                                error=f"KEV feed returned HTTP {exc.code}: {exc.reason}")
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"KEV feed returned HTTP {exc.code}: {exc.reason}")
    except Exception as exc:  # noqa: BLE001 - network/JSON failures surfaced honestly
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"KEV feed request failed: {exc}")

    vulns = data.get("vulnerabilities", []) or []
    match = next((v for v in vulns if str(v.get("cveID", "")).upper() == cve_id), None)

    base_rank = _SEVERITY_RANK.get(severity_hint, 0)
    if match:
        priority = "immediate"
        rank = 100 + base_rank
        severity = "critical"
        evidence = (
            f"{cve_id} IS in CISA's Known Exploited Vulnerabilities catalog "
            f"(added {match.get('dateAdded', 'unknown date')}) — "
            f"{match.get('shortDescription', '')[:200]}"
        )
        remediation = match.get("requiredAction") or "Patch immediately — actively exploited in the wild."
    else:
        priority = severity_hint or "unranked"
        rank = base_rank
        severity = severity_hint or "info"
        evidence = f"{cve_id} is NOT present in CISA's KEV catalog ({len(vulns)} entries checked as of this run)"
        remediation = "No known active exploitation per CISA KEV; prioritize by severity/exposure as usual."

    finding = Finding(
        title=f"Priority for {cve_id}: {priority}",
        severity=severity,
        confidence="certain",
        affected_asset=target,
        evidence=evidence,
        remediation=remediation,
        tool=_TOOL_NAME,
        references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog", cve_id],
    )

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
        summary=f"{cve_id}: priority={priority} (KEV listed={match is not None}, "
                f"severity hint={severity_hint or 'none'})",
        metadata={"cve_id": cve_id, "kev_listed": match is not None, "priority_rank": rank,
                  "kev_entry": match},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "Real prioritization — checks a CVE against CISA's public KEV feed and combines "
                    "it with a severity signal",
    "parameters": {
        "target": "A label, or a string containing a CVE ID",
        "cve_id": "CVE ID to check (e.g. 'CVE-2021-44228')",
        "severity": "Optional severity hint (critical/high/medium/low/info) used when not KEV-listed",
    },
})
