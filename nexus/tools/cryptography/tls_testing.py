#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography tool: Tls Testing
Domain: cryptography

Makes genuine TLS connections and inspects real cipher/protocol/certificate
data — that part was always solid. Previously all findings came back as
plain strings, and this codebase's generic string->severity inference only
promotes a finding's severity if the raw text happens to literally contain
a word like "critical"/"high" — so a genuinely weak cipher or an expired
certificate silently landed at default ("info") severity. Now every finding
carries an explicit, judged severity instead.
"""
import datetime
import socket
import ssl

from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHER_MARKERS = ("NULL", "EXPORT", "RC4", "DES", "3DES", "MD5", "ANON")
_CERT_EXPIRY_WARNING_DAYS = 30


def _protocol_severity(proto: str) -> str:
    return "high" if proto in _WEAK_PROTOCOLS else "info"


def _cipher_severity(cipher_name: str) -> str:
    upper = (cipher_name or "").upper()
    return "high" if any(marker in upper for marker in _WEAK_CIPHER_MARKERS) else "info"


def _cert_expiry_severity(not_after: str) -> tuple[str, str]:
    """Returns (severity, note) for a certificate's notAfter timestamp."""
    if not not_after or not_after == "?":
        return "info", "expiry unknown"
    try:
        expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return "info", "expiry format unrecognized"
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    days_remaining = (expires - now).days
    if days_remaining < 0:
        return "critical", f"expired {abs(days_remaining)} day(s) ago"
    if days_remaining <= _CERT_EXPIRY_WARNING_DAYS:
        return "medium", f"expires in {days_remaining} day(s)"
    return "info", f"expires in {days_remaining} day(s)"


def run(target: str, **kwargs) -> dict:
    """cryptography tool: Tls Testing"""
    findings = []
    try:
        ports = kwargs.get("ports", [443, 8443, 465, 993, 995])
        for port in ports:
            try:
                ctx = get_ssl_context(target, allow_insecure=True)
                with socket.create_connection((target, port), timeout=3) as raw:
                    with ctx.wrap_socket(raw, server_hostname=target) as s:
                        cert = s.getpeercert()
                        cipher = s.cipher()
                        proto = s.version()
                        cipher_name = cipher[0] if cipher else "unknown"

                        proto_sev = _protocol_severity(proto)
                        findings.append({
                            "title": f"TLS protocol on port {port}: {proto}"
                                     + (" (deprecated/weak)" if proto_sev != "info" else " (acceptable)"),
                            "severity": proto_sev,
                            "confidence": "certain",
                            "affected_asset": f"{target}:{port}",
                        })

                        cipher_sev = _cipher_severity(cipher_name)
                        findings.append({
                            "title": f"TLS cipher on port {port}: {cipher_name}"
                                     + (" (weak/deprecated)" if cipher_sev != "info" else " (acceptable)"),
                            "severity": cipher_sev,
                            "confidence": "certain",
                            "affected_asset": f"{target}:{port}",
                        })

                        if cert:
                            subject = dict(x[0] for x in cert.get("subject", []))
                            not_after = cert.get("notAfter", "?")
                            expiry_sev, expiry_note = _cert_expiry_severity(not_after)
                            findings.append({
                                "title": f"Certificate on port {port}: CN={subject.get('commonName', '?')}, "
                                         f"expires={not_after} ({expiry_note})",
                                "severity": expiry_sev,
                                "confidence": "certain",
                                "affected_asset": f"{target}:{port}",
                            })
            except Exception as e:
                findings.append({
                    "title": f"TLS port {port} unreachable or handshake failed: {str(e)[:100]}",
                    "severity": "info",
                    "confidence": "medium",
                    "affected_asset": f"{target}:{port}",
                })
    except Exception as e:
        findings.append({"title": f"Error: {e}", "severity": "low", "confidence": "medium"})
    return {"tool": "cryptography.tls_testing", "domain": "cryptography", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("cryptography.tls_testing", run, metadata={
    "name": "cryptography.tls_testing",
    "domain": "cryptography",
    "status": "completed",
    "description": "cryptography tool: real TLS connections with judged severity (weak protocol/cipher/cert expiry)",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
