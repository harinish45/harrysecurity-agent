#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: HIPAA Audit
Domain: compliance

HIPAA Security Rule Sec. 164.312(e)(1) (transmission security): real
forced-HTTPS check and a real HSTS max-age parse (not just presence).
Previously identical to all 8 other compliance.* tools — caught during
this session's audit.
"""
import re
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry

_MAX_AGE_RE = re.compile(r"max-age=(\d+)", re.IGNORECASE)


def run(target: str, **kwargs) -> dict:
    """compliance tool: HIPAA Audit"""
    findings = []

    try:
        url = f"http://{target}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        final_url = resp.geturl()
        if final_url.startswith("https://"):
            findings.append(f"HTTP request to {url} was redirected to HTTPS ({final_url}) — transmission security enforced")
        else:
            findings.append(
                f"HIPAA 164.312(e)(1) violation: {url} served content directly over cleartext HTTP "
                f"(status {resp.status}) with no redirect to HTTPS — PHI in transit would be unencrypted"
            )
    except Exception as e:
        findings.append(f"Forced-HTTPS check: {str(e)[:60]}")

    try:
        url = f"https://{target}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        hsts = resp.headers.get("Strict-Transport-Security")
        if not hsts:
            findings.append("HIPAA 164.312(e)(1) concern: no Strict-Transport-Security header on HTTPS response")
        else:
            match = _MAX_AGE_RE.search(hsts)
            max_age = int(match.group(1)) if match else 0
            if max_age <= 0:
                findings.append(f"HIPAA 164.312(e)(1) concern: HSTS present but max-age={max_age} (effectively disabled): {hsts}")
            else:
                findings.append(f"HSTS enforced with max-age={max_age}s: {hsts}")
    except Exception as e:
        findings.append(f"HSTS max-age check: {str(e)[:60]}")

    return {"tool": "compliance.hipaa_audit", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.hipaa_audit", run, metadata={
    "name": "compliance.hipaa_audit",
    "domain": "compliance",
    "status": "completed",
    "description": "HIPAA 164.312(e)(1)-relevant checks: forced-HTTPS redirect, HSTS max-age validity",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
