"""Public CVE / KEV feed correlation.

This is deliberately scoped down from a "global threat radar": there is no
dark-web monitoring, no paid threat-intel feed integration, no closed
telemetry sharing. It is two genuinely free, no-auth-required public data
sources correlated against local findings:

- NVD CVE API 2.0 (``https://services.nvd.nist.gov/rest/json/cves/2.0``) --
  keyword search for CVEs matching a software name/version.
- CISA's Known Exploited Vulnerabilities (KEV) catalog
  (``https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json``)
  -- the authoritative "this CVE is being actively exploited in the wild"
  list published by CISA.

Both integrations are defensive by design: network/timeout/parse failures
are logged and degrade to an empty result rather than raising, because the
normal case for a sandboxed/offline test or CI run is "no internet access"
and this module must not crash NEXUS in that case.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

logger = logging.getLogger("nexus.advanced.threat_radar")

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_REQUEST_TIMEOUT_S = 10
_KEV_CACHE_TTL_S = 3600  # 1 hour


def cvss_score_to_severity(score: float | None) -> str:
    """Map a CVSS v3 base score to NEXUS's severity scale."""
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


class ThreatRadar:
    """Correlates software identity / CVE IDs against public NVD and CISA
    KEV data."""

    def __init__(self) -> None:
        self._kev_cache: list[dict[str, Any]] | None = None
        self._kev_cache_time: float = 0.0

    # -- NVD --------------------------------------------------------------

    def check_software(self, software_name: str, version: str | None = None) -> list[dict[str, Any]]:
        """Query the NVD CVE API for CVEs matching ``software_name``
        (optionally narrowed by ``version``), returned as Finding-shaped
        dicts. Returns an empty list on any network/parse failure."""
        if not software_name or not str(software_name).strip():
            return []

        keyword = str(software_name).strip()
        if version:
            keyword = f"{keyword} {str(version).strip()}"

        try:
            response = requests.get(
                NVD_CVE_API_URL,
                params={"keywordSearch": keyword, "resultsPerPage": 20},
                timeout=_REQUEST_TIMEOUT_S,
                headers={"User-Agent": "nexus-strike/threat-radar"},
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:  # network, timeout, HTTP error, bad JSON
            logger.warning("NVD CVE lookup for %r failed: %s", keyword, exc)
            return []

        findings: list[dict[str, Any]] = []
        for vuln in data.get("vulnerabilities", []) or []:
            try:
                findings.append(self._nvd_vuln_to_finding(vuln, software_name))
            except Exception as exc:
                logger.warning("Skipping malformed NVD entry: %s", exc)
                continue
        return findings

    def _nvd_vuln_to_finding(self, vuln: dict[str, Any], software_name: str) -> dict[str, Any]:
        cve = vuln.get("cve", {}) or {}
        cve_id = cve.get("id", "UNKNOWN-CVE")

        description = ""
        for desc in cve.get("descriptions", []) or []:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        score = self._extract_cvss_score(cve)
        severity = cvss_score_to_severity(score)

        references = [
            ref.get("url", "")
            for ref in cve.get("references", []) or []
            if ref.get("url")
        ]

        title = f"{cve_id}: {description[:140]}" if description else cve_id

        return {
            "id": "",
            "title": title,
            "severity": severity,
            "confidence": "high" if score is not None else "medium",
            "affected_asset": software_name,
            "evidence": description or f"CVE {cve_id} matched keyword search for {software_name!r}.",
            "remediation": "Review the CVE record and upgrade/patch the affected software.",
            "references": references,
            "tool": "advanced.threat_radar.nvd",
            "raw": {"cvss_score": score, "cve_id": cve_id},
        }

    @staticmethod
    def _extract_cvss_score(cve: dict[str, Any]) -> float | None:
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            for entry in entries:
                cvss_data = entry.get("cvssData", {}) or {}
                score = cvss_data.get("baseScore")
                if score is not None:
                    try:
                        return float(score)
                    except (TypeError, ValueError):
                        continue
        return None

    # -- CISA KEV -----------------------------------------------------------

    def _get_kev_catalog(self) -> list[dict[str, Any]]:
        now = time.time()
        if self._kev_cache is not None and (now - self._kev_cache_time) < _KEV_CACHE_TTL_S:
            return self._kev_cache

        try:
            response = requests.get(
                CISA_KEV_URL,
                timeout=_REQUEST_TIMEOUT_S,
                headers={"User-Agent": "nexus-strike/threat-radar"},
            )
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", []) or []
        except Exception as exc:
            logger.warning("CISA KEV catalog fetch failed: %s", exc)
            # Don't cache a failure -- allow the next call to retry rather
            # than being stuck returning empty for a full hour.
            return []

        self._kev_cache = vulnerabilities
        self._kev_cache_time = now
        return vulnerabilities

    def check_kev(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        """Return which of ``cve_ids`` appear in the CISA Known Exploited
        Vulnerabilities catalog, as Finding-shaped dicts with
        ``severity="critical"``. Returns an empty list if the catalog can't
        be fetched or none of the given IDs match."""
        if not cve_ids:
            return []

        wanted = {str(c).strip().upper() for c in cve_ids if str(c).strip()}
        if not wanted:
            return []

        catalog = self._get_kev_catalog()
        if not catalog:
            return []

        findings: list[dict[str, Any]] = []
        for entry in catalog:
            cve_id = str(entry.get("cveID", "")).strip().upper()
            if cve_id not in wanted:
                continue
            findings.append(self._kev_entry_to_finding(entry, cve_id))
        return findings

    def _kev_entry_to_finding(self, entry: dict[str, Any], cve_id: str) -> dict[str, Any]:
        vuln_name = entry.get("vulnerabilityName", cve_id)
        vendor = entry.get("vendorProject", "")
        product = entry.get("product", "")
        date_added = entry.get("dateAdded", "unknown")
        due_date = entry.get("dueDate", "")
        short_desc = entry.get("shortDescription", "")

        asset = f"{vendor} {product}".strip() or cve_id

        evidence = (
            f"{cve_id} is listed in CISA's Known Exploited Vulnerabilities "
            f"(KEV) catalog, added {date_added}"
            + (f", remediation due {due_date}" if due_date else "")
            + f". {short_desc}"
        ).strip()

        return {
            "id": "",
            "title": f"{cve_id} ({vuln_name}) is actively exploited (CISA KEV)",
            "severity": "critical",
            "confidence": "certain",
            "affected_asset": asset,
            "evidence": evidence,
            "remediation": entry.get(
                "requiredAction",
                "Patch or mitigate immediately -- this vulnerability is under active exploitation.",
            ),
            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            "tool": "advanced.threat_radar.kev",
            "raw": dict(entry),
        }
