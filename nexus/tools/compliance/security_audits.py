#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: Security Audits
Domain: compliance

A broader composite audit: real response-header hygiene check plus a real
directory-listing-exposure probe (GET a common directory path and check
for an Apache/nginx-style autoindex response). Previously identical to
all 8 other compliance.* tools — caught during this session's audit.
"""
import re
import urllib.error
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry

_SECURITY_HEADERS = ("X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy")
_COMMON_DIRS = ("/assets/", "/images/", "/uploads/", "/backup/", "/files/")
_AUTOINDEX_MARKERS_RE = re.compile(r"Index of /|<title>Index of|directory listing for", re.IGNORECASE)


def run(target: str, **kwargs) -> dict:
    """compliance tool: Security Audits"""
    findings = []

    try:
        url = f"http://{target}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        headers = dict(resp.headers)
        missing = [h for h in _SECURITY_HEADERS if h not in headers]
        if missing:
            findings.append(f"Security header hygiene: {len(missing)}/{len(_SECURITY_HEADERS)} missing: {missing}")
        else:
            findings.append("Security header hygiene: all checked headers present")
    except Exception as e:
        findings.append(f"Header hygiene check: {str(e)[:60]}")

    exposed_dirs = []
    for path in _COMMON_DIRS:
        try:
            url = f"http://{target}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = safe_urlopen(req, timeout=5)
            body = resp.read(4096).decode("utf-8", errors="replace")
            if resp.status == 200 and _AUTOINDEX_MARKERS_RE.search(body):
                exposed_dirs.append(path)
        except Exception:
            continue
    if exposed_dirs:
        findings.append(f"Directory-listing exposure detected at: {exposed_dirs}")
    else:
        findings.append(f"No directory-listing exposure found at common paths {_COMMON_DIRS}")

    return {"tool": "compliance.security_audits", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.security_audits", run, metadata={
    "name": "compliance.security_audits",
    "domain": "compliance",
    "status": "completed",
    "description": "Composite audit: security-header hygiene plus real directory-listing-exposure detection",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
