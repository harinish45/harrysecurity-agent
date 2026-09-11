#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: PCI DSS Audit
Domain: compliance

PCI DSS Requirement 4 (encrypt cardholder data in transit) and Requirement
6 (secure payment-adjacent interfaces): real TLS cipher/protocol strength
check on 443, plus a real check for a payment-shaped form served over
plain HTTP. Previously identical to all 8 other compliance.* tools (a
generic security-header check with zero PCI-specific logic) — caught
during this session's audit.
"""
import re
import socket
import ssl
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "EXPORT", "NULL", "MD5")
_PAYMENT_FIELD_RE = re.compile(r'name=["\']?(cardnumber|card[-_]?number|cvv|cvc|expiry|exp[-_]?date)', re.IGNORECASE)


def run(target: str, **kwargs) -> dict:
    """compliance tool: PCI DSS Audit"""
    findings = []

    try:
        ctx = get_ssl_context(target, allow_insecure=True)
        with socket.create_connection((target, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as tls_sock:
                proto = tls_sock.version()
                cipher_name = tls_sock.cipher()[0]
                if proto in _WEAK_PROTOCOLS:
                    findings.append(f"PCI DSS Req 4 violation: weak TLS protocol {proto} negotiated on port 443")
                else:
                    findings.append(f"TLS protocol on port 443: {proto} (acceptable)")
                if any(marker in cipher_name for marker in _WEAK_CIPHER_MARKERS):
                    findings.append(f"PCI DSS Req 4 violation: weak cipher {cipher_name} negotiated on port 443")
                else:
                    findings.append(f"TLS cipher on port 443: {cipher_name} (acceptable)")
    except (OSError, ssl.SSLError) as e:
        findings.append(f"Could not establish a TLS connection on port 443: {str(e)[:80]}")

    try:
        url = f"http://{target}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        body = resp.read(65536).decode("utf-8", errors="replace")
        if _PAYMENT_FIELD_RE.search(body):
            findings.append(f"PCI DSS Req 4 violation: payment-field-shaped form served over plaintext HTTP at {url}")
    except Exception as e:
        findings.append(f"Plaintext-HTTP payment-form check: {str(e)[:60]}")

    return {"tool": "compliance.pci_dss_audit", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.pci_dss_audit", run, metadata={
    "name": "compliance.pci_dss_audit",
    "domain": "compliance",
    "status": "completed",
    "description": "PCI DSS Req 4/6-relevant checks: TLS protocol/cipher strength on 443, payment-form-over-HTTP detection",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
