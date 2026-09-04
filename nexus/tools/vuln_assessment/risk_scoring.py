#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Risk Scoring
Domain: vuln_assessment
"""
from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context


def run(target: str, **kwargs) -> dict:
    """vuln_assessment tool: Risk Scoring"""
    findings = []
    try:
        import socket
        import urllib.request
        import ssl
        # Port scan
        ports = kwargs.get("ports", [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000, 9090])
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((target, port), timeout=1):
                    open_ports.append(port)
            except:
                pass
        if open_ports:
            findings.append(f"Open ports: {open_ports}")
            # HTTP fingerprint
            for port in open_ports:
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{target}:{port}/"
                try:
                    ctx = get_ssl_context(target, allow_insecure=True)
                    req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                    resp = safe_urlopen(req, timeout=5, context=ctx)
                    server = resp.headers.get("Server", "unknown")
                    findings.append(f"Port {port}: Server={server}")
                except:
                    pass
        else:
            findings.append("No common web ports open")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "vuln_assessment.risk_scoring", "domain": "vuln_assessment", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("vuln_assessment.risk_scoring", run, metadata={
    "name": "vuln_assessment.risk_scoring",
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "vuln_assessment tool: Risk Scoring",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
