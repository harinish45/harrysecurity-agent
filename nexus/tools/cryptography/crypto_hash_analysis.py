#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography tool: Crypto Hash Analysis
Domain: cryptography
"""
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context


def run(target: str, **kwargs) -> dict:
    """cryptography tool: Crypto Hash Analysis"""
    findings = []
    try:
        import socket
        import ssl
        ports = kwargs.get("ports", [443, 8443, 465, 993, 995])
        for port in ports:
            try:
                ctx = get_ssl_context(target, allow_insecure=True)
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
    return {"tool": "cryptography.crypto_hash_analysis", "domain": "cryptography", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("cryptography.crypto_hash_analysis", run, metadata={
    "name": "cryptography.crypto_hash_analysis",
    "domain": "cryptography",
    "status": "completed",
    "description": "cryptography tool: Crypto Hash Analysis",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
