#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: GDPR Audit
Domain: compliance

GDPR Art. 7 (consent) / Art. 13 (transparency): real check for cookies set
before any consent interaction, and real presence/absence check for a
privacy-policy page. Previously identical to all 8 other compliance.*
tools — caught during this session's audit.
"""
import urllib.error
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry

_PRIVACY_PATHS = ("/privacy-policy", "/privacy", "/legal/privacy")


def run(target: str, **kwargs) -> dict:
    """compliance tool: GDPR Audit"""
    findings = []

    try:
        url = f"http://{target}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        set_cookie = resp.headers.get_all("Set-Cookie") or []
        if set_cookie:
            findings.append(
                f"GDPR Art. 7 concern: {len(set_cookie)} cookie(s) set on first page load, before any "
                f"consent interaction is possible: {[c.split(';')[0] for c in set_cookie][:5]}"
            )
        else:
            findings.append("No cookies set on first page load (no pre-consent cookie concern observed)")
    except Exception as e:
        findings.append(f"Cookie-on-load check: {str(e)[:60]}")

    found_privacy_page = False
    for path in _PRIVACY_PATHS:
        try:
            url = f"http://{target}{path}"
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "NexusStrike/1.0"})
            resp = safe_urlopen(req, timeout=5)
            if resp.status < 400:
                findings.append(f"Privacy policy page found: {url} (HTTP {resp.status})")
                found_privacy_page = True
                break
        except urllib.error.HTTPError as e:
            if e.code < 400:
                found_privacy_page = True
                break
        except Exception:
            continue
    if not found_privacy_page:
        findings.append(
            f"GDPR Art. 13 concern: no privacy-policy page found at any of {_PRIVACY_PATHS} — "
            f"transparency obligations may not be met (or the page lives at a non-standard path)"
        )

    return {"tool": "compliance.gdpr_audit", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.gdpr_audit", run, metadata={
    "name": "compliance.gdpr_audit",
    "domain": "compliance",
    "status": "completed",
    "description": "GDPR Art. 7/13-relevant checks: pre-consent cookie detection, privacy-policy page presence",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
