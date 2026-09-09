#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography.pki_reviews
Domain: cryptography

Previously byte-for-byte identical to cryptanalysis.py, crypto_hash_analysis.py,
key_management.py, and certificate_validation.py (a generic TLS-socket scan
dumping plain strings, unrelated to any of those tools' actual names) —
caught during this session's audit.

Now: a real chain-of-trust check. It attempts a TLS handshake with full
certificate verification ON (the default, secure `get_ssl_context()` path
— no `allow_insecure`) against the target; if the handshake succeeds, the
certificate chains to a CA trusted by this system's trust store. If it
fails with an `ssl.SSLCertVerificationError`, the specific verification
failure reason (self-signed, expired, hostname mismatch, unknown CA, etc.)
is reported as the real finding. This extends
`cryptography.certificate_validation`'s certificate fetch/parse for the
individual leaf-certificate checks (expiry, self-signed, hostname), and
adds the chain-of-trust dimension specific to a PKI review.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.cryptography.certificate_validation import (
    _DEFAULT_PORTS,
    evaluate_certificate,
    fetch_and_parse_cert,
)


def _check_chain_of_trust(target: str, port: int, timeout: float = 5.0) -> dict:
    """Real handshake with full verification enabled — succeeds only if the
    certificate chains to a CA in this system's trust store."""
    ctx = get_ssl_context(target, allow_insecure=False)  # verification ON
    try:
        with socket.create_connection((target, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target):
                return {"trusted": True}
    except ssl.SSLCertVerificationError as e:
        return {"trusted": False, "reason": str(e)}
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
        return {"trusted": None, "reason": str(e)[:150]}


def run(target: str, ports: list[int] | None = None, **kwargs: Any) -> dict:
    """Real chain-of-trust review: full-verification handshake + leaf-certificate checks."""
    host = target.strip()
    if not host:
        return tool_result("cryptography.pki_reviews", target, status=STATUS_FAILED, error="Empty target")

    port_list = ports or _DEFAULT_PORTS
    findings: list[Finding] = []
    per_port_errors: dict[int, str] = {}

    for port in port_list:
        chain = _check_chain_of_trust(host, port)
        if chain.get("trusted") is True:
            findings.append(Finding(
                title=f"Certificate chain on {host}:{port} verifies against system trust store",
                severity="info", confidence="certain",
                affected_asset=f"{host}:{port}",
                evidence="TLS handshake succeeded with certificate verification enabled.",
                tool="cryptography.pki_reviews",
            ))
        elif chain.get("trusted") is False:
            findings.append(Finding(
                title=f"Certificate chain on {host}:{port} does NOT verify against system trust store",
                severity="high", confidence="certain",
                affected_asset=f"{host}:{port}",
                evidence=chain.get("reason", ""),
                remediation="Issue from a CA the client trust store recognises, or deploy the "
                            "internal CA's root/intermediate certs to relying clients.",
                tool="cryptography.pki_reviews",
                references=["CWE-295"],
            ))
        else:
            per_port_errors[port] = chain.get("reason", "unreachable")
            continue

        try:
            cert = fetch_and_parse_cert(host, port)
            if cert is not None:
                findings.extend(evaluate_certificate(cert, host, port))
        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError, ValueError) as e:
            per_port_errors.setdefault(port, str(e)[:150])

    if not findings:
        return tool_result(
            "cryptography.pki_reviews", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No TLS endpoints reachable on {host} for PKI review (ports {port_list})",
            metadata={"errors": per_port_errors},
        )

    return tool_result(
        "cryptography.pki_reviews", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"PKI chain-of-trust review completed for {host} across {len(port_list)} port(s)",
        metadata={"errors": per_port_errors, "ports_tested": port_list},
    )


tool_registry.register("cryptography.pki_reviews", run, metadata={
    "name": "cryptography.pki_reviews",
    "domain": "cryptography",
    "status": "completed",
    "description": "Real chain-of-trust review (full-verification TLS handshake) plus leaf-certificate expiry/self-signed/hostname checks",
    "parameters": {
        "target": "Target domain, IP, or URL",
        "ports": "Optional list of ports (default: 443,8443,465,993,995)",
    },
})
