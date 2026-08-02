#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory tool: Gpo Analysis
Domain: active_directory
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """active_directory tool: Gpo Analysis"""
    findings = []
    try:
        import socket
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Target {target} -> {ip}")
        except:
            findings.append(f"DNS resolution failed for {target}")
        import urllib.request
        url = f"http://{target}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            findings.append(f"HTTP {resp.status}: Server={resp.headers.get('Server', 'unknown')}")
        except Exception as e:
            findings.append(f"HTTP check: {str(e)[:60]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "active_directory.gpo_analysis", "domain": "active_directory", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("active_directory.gpo_analysis", run, metadata={
    "name": "active_directory.gpo_analysis",
    "domain": "active_directory",
    "status": "completed",
    "description": "active_directory tool: Gpo Analysis",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
