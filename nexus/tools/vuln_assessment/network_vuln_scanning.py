#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Network Vuln Scanning
Domain: vuln_assessment
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """vuln_assessment tool: Network Vuln Scanning"""
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
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                    server = resp.headers.get("Server", "unknown")
                    findings.append(f"Port {port}: Server={server}")
                except:
                    pass
        else:
            findings.append("No common web ports open")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "vuln_assessment.network_vuln_scanning", "domain": "vuln_assessment", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("vuln_assessment.network_vuln_scanning", run, metadata={
    "name": "vuln_assessment.network_vuln_scanning",
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "vuln_assessment tool: Network Vuln Scanning",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
