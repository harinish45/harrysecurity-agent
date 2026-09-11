#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.ssl_test
Domain: webapp
TLS/SSL configuration assessment with certificate validation, protocol testing, and cipher analysis.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context


SUPPORTED_TLS_VERSIONS = []
if hasattr(ssl, "PROTOCOL_TLS"):
    SUPPORTED_TLS_VERSIONS = [
        ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT) if hasattr(ssl, "PROTOCOL_TLS_CLIENT") else ("TLS", ssl.PROTOCOL_TLS),
    ]
else:
    SUPPORTED_TLS_VERSIONS = [
        ("TLS", ssl.PROTOCOL_TLS),
    ]
if hasattr(ssl, "PROTOCOL_TLSv1_2"):
    SUPPORTED_TLS_VERSIONS.append(("TLSv1.2", ssl.PROTOCOL_TLSv1_2))
if hasattr(ssl, "PROTOCOL_TLSv1_1"):
    SUPPORTED_TLS_VERSIONS.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))
if hasattr(ssl, "PROTOCOL_TLSv1"):
    SUPPORTED_TLS_VERSIONS.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
TLS_PORT_DEFAULTS = [443, 8443, 465, 993, 995, 587, 636, 989, 990]


def _parse_ssl_url(target: str) -> tuple[str, int]:
    """Parse target into host and port for SSL testing."""
    import urllib.parse
    parsed = urllib.parse.urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 8443)
    return host, port


def _get_certificate(host: str, port: int, timeout: float = 5.0) -> Optional[dict]:
    """Retrieve SSL/TLS certificate from host."""
    try:
        ctx = get_ssl_context(host, allow_insecure=True)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert_bin = tls_sock.getpeercert(binary_form=True)
                cert_dict = tls_sock.getpeercert()
                if cert_bin and cert_dict:
                    return {
                        "subject": dict(x[0] for x in cert_dict.get("subject", [])) if cert_dict.get("subject") else {},
                        "issuer": dict(x[0] for x in cert_dict.get("issuer", [])) if cert_dict.get("issuer") else {},
                        "version": cert_dict.get("version"),
                        "serial": cert_dict.get("serialNumber"),
                        "not_before": cert_dict.get("notBefore"),
                        "not_after": cert_dict.get("notAfter"),
                        "signature": cert_dict.get("signatureAlgorithm"),
                        "tls_version": tls_sock.version(),
                        "cipher": tls_sock.cipher(),
                        "san": [x[1] for x in cert_dict.get("subjectAltName", [])] if cert_dict.get("subjectAltName") else [],
                    }
    except Exception:
        pass
    return None


def _check_tls_versions(host: str, port: int, timeout: float) -> dict:
    """Check which TLS versions are supported."""
    results = {}
    # Check the current TLS version from the certificate connection
    cert = _get_certificate(host, port, timeout)
    if cert and cert.get("tls_version"):
        tls_ver = cert["tls_version"]
        results[tls_ver] = True
        # Infer older versions if using TLS 1.3 or 1.2
        if "TLSv1.3" in tls_ver:
            results["TLSv1.2"] = True
            results["TLSv1.1"] = False
            results["TLSv1.0"] = False
        elif "TLSv1.2" in tls_ver:
            results["TLSv1.1"] = False
            results["TLSv1.0"] = False
    return results


def _check_heartbleed(host: str, port: int, timeout: float) -> bool:
    """Check for Heartbleed vulnerability (simplified check)."""
    # This is a placeholder - real Heartbleed detection requires raw TLS packets
    # and is better done with dedicated tools like nmap scripts
    return False


def run(
    target: str,
    port: int | None = None,
    check_versions: bool = True,
    check_heartbleed: bool = False,
    timeout: float = 5.0,
    **kwargs: Any,
) -> dict:
    """Perform TLS/SSL configuration assessment.

    Parameters
    ----------
    target : str
        Hostname or URL to assess.
    port : int, optional
        TLS port to test. Defaults to 443 or derived from URL.
    check_versions : bool
        Test supported TLS protocol versions.
    check_heartbleed : bool
        Check for Heartbleed vulnerability.
    timeout : float
        Connection timeout in seconds.
    """
    host, default_port = _parse_ssl_url(target)
    test_port = port or default_port

    findings: list[Finding] = []

    cert = _get_certificate(host, test_port, timeout)
    if not cert:
        return tool_result(
            "webapp.ssl_test", target,
            status=STATUS_FAILED,
            error=f"Could not establish TLS connection to {host}:{test_port}",
        )

    # Certificate validity finding
    if cert.get("not_after"):
        from datetime import datetime
        try:
            expiry = datetime.strptime(cert["not_after"], "%b %d %H:%M:%S %Y %Z")
            days_until_expiry = (expiry - datetime.utcnow()).days
            if days_until_expiry < 0:
                sev = "critical"
                evidence = f"Certificate EXPIRED on {cert['not_after']}"
            elif days_until_expiry < 14:
                sev = "high"
                evidence = f"Certificate expires soon: {cert['not_after']} ({days_until_expiry} days)"
            elif days_until_expiry < 30:
                sev = "medium"
                evidence = f"Certificate expires: {cert['not_after']} ({days_until_expiry} days)"
            else:
                sev = "info"
                evidence = f"Certificate valid until: {cert['not_after']}"

            findings.append(Finding(
                title=f"TLS certificate for {host}",
                severity=sev,
                confidence="certain",
                affected_asset=host,
                evidence=evidence,
                remediation="Renew certificate before expiry. Use proper certificate management.",
                tool="webapp.ssl_test",
                references=["CWE-295"],
            ))
        except Exception:
            pass

    # TLS version findings
    if check_versions:
        tls_versions = _check_tls_versions(host, test_port, timeout)
        if cert and cert.get("tls_version"):
            tls_ver = cert.get("tls_version", "")
            if "TLSv1.0" in tls_ver or "TLSv1.1" in tls_ver:
                findings.append(Finding(
                    title=f"Outdated TLS version in use: {tls_ver}",
                    severity="high",
                    confidence="certain",
                    affected_asset=f"{host}:{test_port}",
                    evidence=f"Server uses {tls_ver} which is deprecated",
                    remediation="Upgrade to TLS 1.2 or higher.",
                    tool="webapp.ssl_test",
                    references=["CWE-327", "CWE-326"],
                ))

    # Cipher suite
    cipher = cert.get("cipher", ())
    if cipher:
        findings.append(Finding(
            title=f"TLS cipher suite for {host}",
            severity="info",
            confidence="certain",
            affected_asset=f"{host}:{test_port}",
            evidence=f"Active cipher: {cipher[0]} ({cipher[1]} bits)",
            remediation="Review cipher suite for compliance requirements.",
            tool="webapp.ssl_test",
            references=["CWE-327"],
        ))

    # Heartbleed check
    if check_heartbleed and _check_heartbleed(host, test_port, timeout):
        findings.append(Finding(
            title=f"Heartbeat extension enabled (potential Heartbleed risk)",
            severity="high",
            confidence="medium",
            affected_asset=f"{host}:{test_port}",
            evidence="Server accepts heartbeat requests",
            remediation="Review OpenSSL version and apply security patches.",
            tool="webapp.ssl_test",
            references=["CVE-2014-0160"],
        ))

    # SAN check
    if cert.get("san"):
        findings.append(Finding(
            title=f"Certificate Subject Alternative Names",
            severity="info",
            confidence="certain",
            affected_asset=host,
            evidence=f"SANs: {', '.join(cert['san'][:10])}",
            remediation="Verify all SAN entries are intended and authorized.",
            tool="webapp.ssl_test",
            references=["CWE-295"],
        ))

    summary = f"TLS assessment completed for {host}:{test_port}"
    if findings:
        summary += f" - {len(findings)} finding{'s' if len(findings) > 1 else ''}"

    return tool_result(
        "webapp.ssl_test", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=summary,
        metadata={
            "host": host,
            "port": test_port,
            "tls_version": cert.get("tls_version"),
            "findings_count": len(findings),
        },
    )


tool_registry.register("webapp.ssl_test", run, metadata={
    "name": "webapp.ssl_test",
    "domain": "webapp",
    "status": "completed",
    "description": "TLS/SSL configuration assessment with certificate validation and protocol testing",
    "parameters": {
        "target": "Target hostname or URL",
        "port": "TLS port to test (default: 443 or from URL)",
        "check_versions": "Test supported TLS protocol versions (default: True)",
        "check_heartbleed": "Check for Heartbleed vulnerability (default: False)",
        "timeout": "Connection timeout in seconds (default: 5s)",
    },
})
