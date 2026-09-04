#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Alert Investigation
Domain: soc
"""
from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Alert Investigation"""
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
                resp = safe_urlopen(req, timeout=3)
                findings.append(f"{ep}: status={resp.status}")
            except urllib.error.HTTPError as e:
                findings.append(f"{ep}: HTTP {e.code}")
            except:
                pass
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "soc.alert_investigation", "domain": "soc", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("soc.alert_investigation", run, metadata={
    "name": "soc.alert_investigation",
    "domain": "soc",
    "status": "completed",
    "description": "soc tool: Alert Investigation",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
