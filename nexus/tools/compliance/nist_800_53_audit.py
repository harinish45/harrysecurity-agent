#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: NIST 800-53 Audit
Domain: compliance

NIST 800-53 CM-8 (system component inventory / information leakage via
version banners) and SI-2-adjacent (flaw remediation depends on knowing
what's deployed, but so does an attacker): real Server/X-Powered-By banner
disclosure check, plus a real robots.txt-disclosed sensitive-path check.
Previously identical to all 8 other compliance.* tools — caught during
this session's audit.
"""
import urllib.error
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry

_VERSION_LEAK_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")
_SENSITIVE_PATH_MARKERS = ("admin", "login", "wp-admin", "manage", "console", "internal", "private", "backup", "config")


def run(target: str, **kwargs) -> dict:
    """compliance tool: NIST 800-53 Audit"""
    findings = []

    try:
        url = f"http://{target}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        for header in _VERSION_LEAK_HEADERS:
            value = resp.headers.get(header)
            if value:
                findings.append(f"NIST 800-53 CM-8 concern: {header} discloses software/version info: '{value}'")
        if not any(resp.headers.get(h) for h in _VERSION_LEAK_HEADERS):
            findings.append("No software/version-disclosing response headers observed")
    except Exception as e:
        findings.append(f"Banner disclosure check: {str(e)[:60]}")

    try:
        url = f"http://{target}/robots.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        body = resp.read(8192).decode("utf-8", errors="replace")
        disclosed = []
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith(("disallow:", "allow:")):
                path = stripped.split(":", 1)[1].strip()
                if any(marker in path.lower() for marker in _SENSITIVE_PATH_MARKERS):
                    disclosed.append(path)
        if disclosed:
            findings.append(
                f"NIST 800-53 CM-8 concern: robots.txt discloses {len(disclosed)} sensitive-looking path(s) "
                f"an attacker wouldn't otherwise have found: {disclosed[:10]}"
            )
        else:
            findings.append("robots.txt present with no obviously sensitive path disclosures")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            findings.append("No robots.txt found (nothing to disclose)")
        else:
            findings.append(f"robots.txt check: HTTP {e.code}")
    except Exception as e:
        findings.append(f"robots.txt disclosure check: {str(e)[:60]}")

    return {"tool": "compliance.nist_800_53_audit", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.nist_800_53_audit", run, metadata={
    "name": "compliance.nist_800_53_audit",
    "domain": "compliance",
    "status": "completed",
    "description": "NIST 800-53 CM-8-relevant checks: version-banner disclosure, robots.txt sensitive-path disclosure",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
