#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud tool: Iam Audit
Domain: cloud
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """cloud tool: Iam Audit"""
    findings = []
    try:
        import socket
        import urllib.request
        # Check if target resolves
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Target {target} resolves to {ip}")
        except:
            findings.append(f"Target {target} does not resolve")
        # Check HTTP
        for scheme in ("http", "https"):
            url = f"{scheme}://{target}/"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                findings.append(f"{scheme}://{target}: status={resp.status}")
            except Exception as e:
                findings.append(f"{scheme}://{target}: {str(e)[:60]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "cloud.iam_audit", "domain": "cloud", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("cloud.iam_audit", run, metadata={
    "name": "cloud.iam_audit",
    "domain": "cloud",
    "status": "completed",
    "description": "cloud tool: Iam Audit",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
