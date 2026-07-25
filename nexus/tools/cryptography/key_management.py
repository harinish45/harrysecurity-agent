#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography tool: Key Management
Domain: cryptography
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """cryptography tool: Key Management"""
    findings = []
    try:
        import socket
        import ssl
        ports = kwargs.get("ports", [443, 8443, 465, 993, 995])
        for port in ports:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target, port), timeout=3) as raw:
                    with ctx.wrap_socket(raw, server_hostname=target) as s:
                        cert = s.getpeercert()
                        cipher = s.cipher()
                        proto = s.version()
                        findings.append(f"SSL port {port}: proto={proto}, cipher={cipher[0]}")
                        if cert:
                            subject = dict(x[0] for x in cert.get("subject", []))
                            findings.append(f"  CN={subject.get('commonName', '?')}, expires={cert.get('notAfter', '?')}")
            except Exception as e:
                findings.append(f"SSL port {port}: {str(e)[:60]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "cryptography.key_management", "domain": "cryptography", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("cryptography.key_management", run, metadata={
    "name": "cryptography.key_management",
    "domain": "cryptography",
    "status": "completed",
    "description": "cryptography tool: Key Management",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
