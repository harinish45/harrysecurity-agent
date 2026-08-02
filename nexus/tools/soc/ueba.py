#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Ueba
Domain: soc
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Ueba"""
    findings = []
    try:
        import socket
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Target {target} -> {ip}")
        except:
            findings.append(f"DNS resolution failed for {target}")
        for ep in ["/alerts", "/logs", "/api/v1/alerts", "/siem"]:
            url = f"http://{target}{ep}"
            try:
                import urllib.request
                req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                resp = urllib.request.urlopen(req, timeout=3)
                findings.append(f"{ep}: status={resp.status}")
            except urllib.error.HTTPError as e:
                findings.append(f"{ep}: HTTP {e.code}")
            except:
                pass
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "soc.ueba", "domain": "soc", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("soc.ueba", run, metadata={
    "name": "soc.ueba",
    "domain": "soc",
    "status": "completed",
    "description": "soc tool: Ueba",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
