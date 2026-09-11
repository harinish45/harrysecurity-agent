#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: Policy Reviews
Domain: compliance

Real presence/content check for RFC 9116 security.txt and robots.txt —
whether the target publishes the disclosure/scope policy documents an
external researcher or auditor would look for first. Previously identical
to all 8 other compliance.* tools — caught during this session's audit.
"""
import urllib.error
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry

_REQUIRED_SECURITY_TXT_FIELDS = ("Contact", "Expires")


def run(target: str, **kwargs) -> dict:
    """compliance tool: Policy Reviews"""
    findings = []

    try:
        url = f"http://{target}/.well-known/security.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        body = resp.read(8192).decode("utf-8", errors="replace")
        findings.append(f"security.txt found at {url}")
        present_fields = [line.split(":", 1)[0].strip() for line in body.splitlines() if ":" in line]
        for field in _REQUIRED_SECURITY_TXT_FIELDS:
            if field in present_fields:
                findings.append(f"security.txt has required field '{field}'")
            else:
                findings.append(f"security.txt is missing recommended field '{field}' (RFC 9116)")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            findings.append("No security.txt found at /.well-known/security.txt (RFC 9116 not implemented)")
        else:
            findings.append(f"security.txt check: HTTP {e.code}")
    except Exception as e:
        findings.append(f"security.txt check: {str(e)[:60]}")

    try:
        url = f"http://{target}/robots.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        findings.append(f"robots.txt present at {url} ({len(resp.read(8192))} bytes)")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            findings.append("No robots.txt found")
        else:
            findings.append(f"robots.txt check: HTTP {e.code}")
    except Exception as e:
        findings.append(f"robots.txt check: {str(e)[:60]}")

    return {"tool": "compliance.policy_reviews", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.policy_reviews", run, metadata={
    "name": "compliance.policy_reviews",
    "domain": "compliance",
    "status": "completed",
    "description": "Real presence/content checks for RFC 9116 security.txt and robots.txt",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
