#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.cert_transparency
Domain: reconnaissance

Previously one of 13 tools (7 reconnaissance + 6 ai_security) sharing
byte-for-byte identical fake logic (DNS resolve + bare HTTP GET on `/`,
unrelated to what each tool claimed to do) — caught during a follow-up
audit. Now performs a real query against crt.sh's free public Certificate
Transparency log JSON API (no API key required) and parses genuine
certificate/subdomain data from the response.
"""
from __future__ import annotations

import json
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
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_TOOL_NAME = "reconnaissance.cert_transparency"
_USER_AGENT = "NEXUS-STRIKE/0.2.0 (CertTransparency)"
_MAX_FINDINGS = 25  # crt.sh can return thousands of rows for large orgs


def _query_crtsh(domain: str, timeout: int = 12) -> Any:
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    ctx = get_ssl_context("crt.sh")
    resp = safe_urlopen(req, timeout=timeout, context=ctx)
    body = resp.read()
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    return json.loads(text)


def run(target: str, **kwargs: Any) -> dict:
    """Query crt.sh Certificate Transparency logs for real cert/subdomain data."""
    domain = target.strip().lower()
    if not domain:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error="Empty target")

    try:
        entries = _query_crtsh(domain)
    except urllib.error.HTTPError as e:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
            error=f"crt.sh returned HTTP {e.code}: {e.reason}",
        )
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE, error=f"crt.sh unreachable: {e}")
    except (json.JSONDecodeError, ValueError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"crt.sh returned unparseable data: {e}")

    if not entries:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"No certificate transparency log entries found for {domain} on crt.sh",
        )

    findings: list[Finding] = []
    subdomains: set[str] = set()
    seen_cert_ids: set = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "") or ""
        names = {n.strip().lower() for n in name_value.split("\n") if n.strip()}
        for name in names:
            clean = name[2:] if name.startswith("*.") else name
            if clean and clean != domain:
                subdomains.add(clean)

        cert_id = entry.get("id")
        if cert_id in seen_cert_ids:
            continue
        seen_cert_ids.add(cert_id)
        if len(findings) < _MAX_FINDINGS:
            findings.append(Finding(
                title=f"Certificate issued for {entry.get('common_name') or domain}",
                severity="info",
                confidence="certain",
                affected_asset=domain,
                evidence=(
                    f"crt.sh id={cert_id}, issuer={entry.get('issuer_name', 'unknown')}, "
                    f"not_before={entry.get('not_before')}, not_after={entry.get('not_after')}, "
                    f"names={sorted(names)}"
                ),
                remediation="Verify all certificates and subdomains are intentional and expected; "
                            "investigate any unrecognized names for shadow IT or forgotten infrastructure.",
                tool=_TOOL_NAME,
                references=[f"https://crt.sh/?id={cert_id}"] if cert_id else ["CWE-200"],
            ))

    if subdomains:
        findings.append(Finding(
            title=f"{len(subdomains)} distinct subdomains discovered via certificate transparency for {domain}",
            severity="info",
            confidence="certain",
            affected_asset=domain,
            evidence=f"Subdomains: {sorted(subdomains)[:50]}",
            remediation="Confirm all listed subdomains are known/authorized assets; investigate unrecognized ones.",
            tool=_TOOL_NAME,
            references=["CWE-200"],
        ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Found {len(entries)} CT log entries and {len(subdomains)} distinct subdomains for {domain}",
        metadata={"total_entries": len(entries), "subdomains": sorted(subdomains)},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Queries crt.sh's free public Certificate Transparency log API for real certificate "
                    "and subdomain data (no API key required)",
    "parameters": {
        "target": "Target domain to search certificate transparency logs for",
    },
})
