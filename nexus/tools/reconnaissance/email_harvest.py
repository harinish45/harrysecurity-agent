#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance tool: Email Harvest
Domain: reconnaissance
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """reconnaissance tool: Email Harvest"""
    findings = []
    try:
        import socket
        import urllib.request
        # DNS resolution
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Resolved {target} -> {ip}")
        except Exception as e:
            findings.append(f"DNS resolution failed: {e}")
        # HTTP check
        for scheme in ("http", "https"):
            url = f"{scheme}://{target}/"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                findings.append(f"HTTP {scheme}://{target}: status={resp.status}, Server={resp.headers.get('Server', 'unknown')}")
            except Exception as e:
                findings.append(f"HTTP {scheme}://{target}: {str(e)[:80]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "reconnaissance.email_harvest", "domain": "reconnaissance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("reconnaissance.email_harvest", run, metadata={
    "name": "reconnaissance.email_harvest",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "reconnaissance tool: Email Harvest",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
