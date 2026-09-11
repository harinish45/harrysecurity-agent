#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.social_osint
Domain: reconnaissance

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to social-presence OSINT).
Caught during a follow-up audit. Now performs real, ToS-friendly presence
checks via HTTP HEAD requests to common social/professional-platform URL
patterns for the target name — confirming existence via status code only,
never scraping content that requires login or violates a platform's ToS.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_FAILED, STATUS_NO_FINDINGS, tool_result
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_TOOL_NAME = "reconnaissance.social_osint"
_USER_AGENT = "NEXUS-STRIKE/0.2.0 (SocialOsint)"

# Public URL patterns checkable via a plain HEAD request without login —
# each entry is (platform, url_template).
_PLATFORM_PATTERNS = [
    ("GitHub", "https://github.com/{name}"),
    ("GitHub org", "https://github.com/orgs/{name}"),
    ("npm", "https://www.npmjs.com/~{name}"),
    ("PyPI user", "https://pypi.org/user/{name}/"),
    ("LinkedIn company", "https://www.linkedin.com/company/{name}"),
    ("Twitter/X", "https://x.com/{name}"),
    ("Crunchbase", "https://www.crunchbase.com/organization/{name}"),
]


def _check_presence(url: str, timeout: int = 6) -> int | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="HEAD")
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def run(target: str, **kwargs: Any) -> dict:
    """Real, ToS-friendly HEAD-request presence check across common public platforms."""
    name = target.strip().lower().replace(" ", "-")
    if not name:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    checked = 0
    for platform, template in _PLATFORM_PATTERNS:
        url = template.format(name=name)
        status = _check_presence(url)
        checked += 1
        if status is not None and status < 400:
            findings.append(Finding(
                title=f"Public presence found on {platform} for '{name}'",
                severity="info",
                confidence="medium",
                affected_asset=name,
                evidence=f"Real HTTP HEAD request to {url} returned status {status}",
                remediation="Review this public presence for information disclosure relevant to the "
                            "assessment (org structure, technology stack, employee names).",
                tool=_TOOL_NAME,
                references=[url],
            ))

    if not findings:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"No public presence found for '{name}' across {checked} checked platform(s)",
        )

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Found real public presence on {len(findings)} of {checked} checked platform(s) for '{name}'",
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Real, ToS-friendly public-presence check (HTTP HEAD requests) across common "
                    "social/professional platform URL patterns for the target name",
    "parameters": {"target": "Target organization/username to check for public presence"},
})
