#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam tool: Ad Iam
Domain: iam
"""
from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """iam tool: Ad Iam"""
    findings = []
    try:
        import socket
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Target {target} -> {ip}")
        except:
            findings.append(f"DNS resolution failed for {target}")
        # Check common auth endpoints
        endpoints = ["/login", "/admin", "/api/auth", "/oauth", "/saml", "/.well-known/openid-configuration"]
        import urllib.request
        for ep in endpoints:
            url = f"http://{target}{ep}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                resp = safe_urlopen(req, timeout=3)
                findings.append(f"{ep}: status={resp.status}")
            except urllib.error.HTTPError as e:
                findings.append(f"{ep}: HTTP {e.code}")
            except:
                pass
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "iam.ad_iam", "domain": "iam", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("iam.ad_iam", run, metadata={
    "name": "iam.ad_iam",
    "domain": "iam",
    "status": "completed",
    "description": "iam tool: Ad Iam",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
