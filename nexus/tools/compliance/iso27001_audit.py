#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: ISO 27001 Audit
Domain: compliance

ISO/IEC 27001 Annex A.8 (asset/tech controls) — A.8.24-adjacent
cryptographic controls and A.8.26-adjacent application-security
requirements: real HTTP response-header hygiene check (the specific
headers checked are the access-control/anti-clickjacking/content-type-
sniffing/transport-security controls Annex A.8 calls out), reported
against a named ISO 27001 control ID per header rather than a bare
header-presence list.
"""
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.tools.registry import tool_registry

# header -> (ISO 27001 Annex A control this maps to, why it matters)
_CONTROL_HEADERS = {
    "Strict-Transport-Security": ("A.8.24", "cryptographic controls — enforces encrypted transport"),
    "Content-Security-Policy": ("A.8.26", "application security requirements — mitigates injection/XSS"),
    "X-Frame-Options": ("A.8.26", "application security requirements — mitigates clickjacking"),
    "X-Content-Type-Options": ("A.8.26", "application security requirements — mitigates MIME-sniffing"),
}


def run(target: str, **kwargs) -> dict:
    """compliance tool: ISO 27001 Audit"""
    findings = []
    try:
        import socket
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Target {target} -> {ip}")
        except socket.gaierror as e:
            findings.append(f"DNS resolution failed for {target}: {e}")

        url = f"https://{target}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = safe_urlopen(req, timeout=5)
            headers = dict(resp.headers)
            for header, (control, why) in _CONTROL_HEADERS.items():
                if header in headers:
                    findings.append(f"[{control}] {header}: {headers[header]}")
                else:
                    findings.append(f"[{control}] {header}: MISSING — {why}")
        except Exception as e:
            findings.append(f"HTTPS control-header check: {str(e)[:60]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "compliance.iso27001_audit", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.iso27001_audit", run, metadata={
    "name": "compliance.iso27001_audit",
    "domain": "compliance",
    "status": "completed",
    "description": "ISO 27001 Annex A.8-relevant checks: crypto/app-security response headers mapped to specific control IDs",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
