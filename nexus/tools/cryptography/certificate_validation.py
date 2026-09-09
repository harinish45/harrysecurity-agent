#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography.certificate_validation
Domain: cryptography

Previously byte-for-byte identical to cryptanalysis.py, crypto_hash_analysis.py,
key_management.py, and pki_reviews.py (a generic TLS-socket scan dumping
plain strings, unrelated to any of those tools' actual names) — caught
during this session's audit.

Now: a real X.509 certificate fetch (`ssl.get_server_certificate`) and
parse (via the `cryptography` package, which IS in requirements.txt/venv)
per port, with real judged findings for the actual validation checks a
certificate-validation tool should perform: expiry, self-signed status,
and hostname/SAN match against `target`.
"""
from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

_DEFAULT_PORTS = [443, 8443, 465, 993, 995]
_EXPIRY_WARNING_DAYS = 30


def fetch_and_parse_cert(target: str, port: int, timeout: float = 5.0) -> "x509.Certificate | None":
    """Fetch the peer certificate from target:port and parse it with `cryptography`.
    Shared with pki_reviews.py's chain-of-trust check."""
    ctx = get_ssl_context(target, allow_insecure=True)
    with socket.create_connection((target, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=target) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
    if not der:
        return None
    return x509.load_der_x509_certificate(der, default_backend())


def evaluate_certificate(cert: "x509.Certificate", target: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    days_remaining = (not_after - now).days

    if days_remaining < 0:
        findings.append(Finding(
            title=f"Certificate on {target}:{port} is EXPIRED ({abs(days_remaining)} day(s) ago)",
            severity="critical", confidence="certain",
            affected_asset=f"{target}:{port}",
            evidence=f"notAfter={not_after.isoformat()}",
            remediation="Renew the certificate immediately.",
            tool="cryptography.certificate_validation",
        ))
    elif days_remaining <= _EXPIRY_WARNING_DAYS:
        findings.append(Finding(
            title=f"Certificate on {target}:{port} expires soon ({days_remaining} day(s))",
            severity="medium", confidence="certain",
            affected_asset=f"{target}:{port}",
            evidence=f"notAfter={not_after.isoformat()}",
            remediation="Renew the certificate before it expires.",
            tool="cryptography.certificate_validation",
        ))
    else:
        findings.append(Finding(
            title=f"Certificate on {target}:{port} validity OK ({days_remaining} day(s) remaining)",
            severity="info", confidence="certain",
            affected_asset=f"{target}:{port}",
            evidence=f"notBefore={not_before.isoformat()}, notAfter={not_after.isoformat()}",
            tool="cryptography.certificate_validation",
        ))

    is_self_signed = cert.issuer == cert.subject
    if is_self_signed:
        findings.append(Finding(
            title=f"Certificate on {target}:{port} is self-signed",
            severity="medium", confidence="certain",
            affected_asset=f"{target}:{port}",
            evidence=f"issuer == subject: {cert.subject.rfc4514_string()}",
            remediation="Use a certificate issued by a trusted public or internal CA for "
                        "anything beyond local testing.",
            tool="cryptography.certificate_validation",
            references=["CWE-295"],
        ))

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = None
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []

    candidate_names = set(san_names)
    if cn:
        candidate_names.add(cn)
    hostname_matches = any(
        name == target or (name.startswith("*.") and target.endswith(name[1:]))
        for name in candidate_names
    )
    if not hostname_matches and candidate_names:
        findings.append(Finding(
            title=f"Certificate on {target}:{port} does not match hostname {target}",
            severity="high", confidence="certain",
            affected_asset=f"{target}:{port}",
            evidence=f"CN={cn}, SAN={san_names}, requested hostname={target}",
            remediation="Issue a certificate whose CN/SAN actually covers this hostname.",
            tool="cryptography.certificate_validation",
            references=["CWE-297"],
        ))

    return findings


def run(target: str, ports: list[int] | None = None, **kwargs: Any) -> dict:
    """Real X.509 certificate fetch + expiry/self-signed/hostname-match validation."""
    host = target.strip()
    if not host:
        return tool_result("cryptography.certificate_validation", target, status=STATUS_FAILED, error="Empty target")

    port_list = ports or _DEFAULT_PORTS
    findings: list[Finding] = []
    per_port_errors: dict[int, str] = {}

    for port in port_list:
        try:
            cert = fetch_and_parse_cert(host, port)
            if cert is None:
                per_port_errors[port] = "no certificate returned"
                continue
            findings.extend(evaluate_certificate(cert, host, port))
        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError, ValueError) as e:
            per_port_errors[port] = str(e)[:150]

    if not findings:
        return tool_result(
            "cryptography.certificate_validation", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No TLS certificates retrieved from {host} on ports {port_list}",
            metadata={"errors": per_port_errors},
        )

    return tool_result(
        "cryptography.certificate_validation", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Validated {len([p for p in port_list if p not in per_port_errors])} certificate(s) on {host}",
        metadata={"errors": per_port_errors, "ports_tested": port_list},
    )


tool_registry.register("cryptography.certificate_validation", run, metadata={
    "name": "cryptography.certificate_validation",
    "domain": "cryptography",
    "status": "completed",
    "description": "Real X.509 certificate fetch+parse with judged expiry/self-signed/hostname-match findings",
    "parameters": {
        "target": "Target domain, IP, or URL",
        "ports": "Optional list of ports (default: 443,8443,465,993,995)",
    },
})
