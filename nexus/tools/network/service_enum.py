# -*- coding: utf-8 -*-
"""
NEXUS-STRIKE — network.service_enum
Domain: network
Deep service enumeration with banner grabbing, version detection, and protocol identification.
"""
from __future__ import annotations

import socket
import ssl
import struct
import time
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

PROBES: dict[int, bytes] = {
    21: b"SYST\r\n",
    22: b"\r\n",
    25: b"EHLO localhost\r\n",
    53: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: b"",
    445: b"\x00\x00\x00\x00",
    3306: b"\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f\x00\x00\x00\x00\x00\x00\x00\x00",
}

KNOWN_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE", 587: "SMTP-Submit", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "OracleDB",
    1701: "L2TP", 1723: "PPTP", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3128: "Squid", 3306: "MySQL", 3389: "RDP",
    3478: "STUN", 4000: "Default", 4369: "Erlang", 5000: "Flask",
    5432: "PostgreSQL", 5555: "ADB", 5601: "Kibana", 5672: "AMQP",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6443: "Kubernetes", 7070: "Default", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Default",
    9000: "SonarQube", 9090: "HTTP-Alt2", 9100: "Node-Exporter",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    9418: "Git", 9999: "Default", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB-Shard", 50000: "DB2",
    50070: "HDFS", 61616: "ActiveMQ",
}

TLS_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 587}


def _grab_banner(sock: socket.socket, port: int, timeout: float = 2.0, max_bytes: int = 4096) -> str:
    """Grab a service banner from an open socket."""
    try:
        sock.settimeout(timeout)
        probe = PROBES.get(port, b"")
        if probe:
            sock.sendall(probe)
        data = sock.recv(max_bytes)
        return data.decode("utf-8", errors="replace").strip()[:512]
    except (OSError, socket.timeout):
        return ""


def _check_tls(host: str, port: int, timeout: float) -> dict:
    """Attempt TLS handshake and return certificate info."""
    if port not in TLS_PORTS:
        return {}
    try:
        ctx = get_ssl_context(host, allow_insecure=True)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=True)
                version = tls_sock.version()
                cipher = tls_sock.cipher()
                result = {
                    "available": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[1] if cipher else 0,
                }
                if cert:
                    try:
                        parsed = tls_sock.getpeercert()
                        result["subject"] = dict(x[0] for x in parsed.get("subject", [])) if parsed.get("subject") else {}
                        result["issuer"] = dict(x[0] for x in parsed.get("issuer", [])) if parsed.get("issuer") else {}
                        result["not_after"] = parsed.get("notAfter", "")
                        result["not_before"] = parsed.get("notBefore", "")
                    except Exception:
                        pass
                return result
    except Exception:
        return {"available": False}


def _probe_port(host: str, port: int, timeout: float = 2.0) -> Optional[dict]:
    """Probe a single TCP port. Returns port info or None."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = _grab_banner(sock, port, timeout)
            tls = _check_tls(host, port, timeout)
            return {
                "port": port,
                "state": "open",
                "service": KNOWN_SERVICES.get(port, "unknown"),
                "banner": banner,
                "tls": tls,
            }
    except (socket.timeout, OSError, ConnectionRefusedError):
        return None


def _classify_tls_version(version: str) -> tuple[str, str]:
    """Classify TLS version severity."""
    if version.startswith("TLSv1.0") or version.startswith("TLSv1.1"):
        return "high", "Outdated TLS version (TLS 1.0/1.1) detected"
    if version.startswith("SSL"):
        return "critical", "SSL protocol detected (deprecated and insecure)"
    return "info", "Modern TLS version in use"


def run(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    max_workers: int = 100,
    **kwargs: Any,
) -> dict:
    """Perform service enumeration against target with banner grabbing and TLS inspection.

    Parameters
    ----------
    target : str
        IP address or hostname to enumerate.
    ports : list[int], optional
        Port list. Defaults to all known service ports.
    timeout : float
        Per-port connection timeout in seconds.
    max_workers : int
        Maximum concurrent probe threads.
    """
    import concurrent.futures

    host = target.strip()
    if not host:
        return tool_result("network.service_enum", target, status=STATUS_FAILED, error="Empty target")

    port_list = ports or sorted(KNOWN_SERVICES.keys())
    findings: list[Finding] = []
    open_ports: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        fut_map = {executor.submit(_probe_port, host, p, timeout): p for p in port_list}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                result = fut.result()
                if result:
                    open_ports.append(result)
            except Exception:
                pass

    open_ports.sort(key=lambda x: x["port"])

    if not open_ports:
        return tool_result(
            "network.service_enum", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No open ports found on {host} among {len(port_list)} tested ports",
        )

    for p in open_ports:
        sev = "high" if p["service"] in ("SSH", "Telnet", "FTP", "RDP", "VNC", "SMB") else \
            "medium" if p["service"] in ("HTTP", "MySQL", "MSSQL", "Redis", "MongoDB", "Elasticsearch") else \
            "low"

        evidence_parts = [f"Port {p['port']}/{p['service']} open"]
        if p.get("banner"):
            evidence_parts.append(f"Banner: {p['banner'][:200]}")
        if p.get("tls", {}).get("available"):
            tls = p["tls"]
            evidence_parts.append(f"TLS: version={tls.get('version')} cipher={tls.get('cipher')}")
            if tls.get("subject"):
                evidence_parts.append(f"Cert subject: {tls['subject']}")
            if tls.get("not_after"):
                evidence_parts.append(f"Cert expires: {tls['not_after']}")
            tls_sev, tls_msg = _classify_tls_version(tls.get("version", ""))
            if tls_sev in ("high", "critical"):
                sev = tls_sev
                evidence_parts.append(f"TLS issue: {tls_msg}")

        evidence = "\n".join(evidence_parts)

        remediation = f"Review open port {p['port']} ({p['service']}). Close if not required."
        if p["service"] in ("Telnet", "FTP"):
            remediation = f"Replace {p['service']} with secure alternatives (SSH/SFTP)."
        elif p["service"] in ("Redis", "MongoDB", "Elasticsearch"):
            remediation = f"Ensure {p['service']} is bound to localhost and requires authentication."
        elif p.get("tls", {}).get("version", "").startswith(("TLSv1.0", "TLSv1.1", "SSL")):
            remediation = f"Upgrade TLS configuration on port {p['port']} to TLS 1.2+."

        findings.append(Finding(
            title=f"Open port {p['port']} ({p['service']}) on {host}",
            severity=sev,
            confidence="certain",
            affected_asset=f"{host}:{p['port']}",
            evidence=evidence,
            remediation=remediation,
            tool="network.service_enum",
            references=["CWE-200", "CWE-16"] if p["service"] in ("Telnet", "FTP") else [],
        ))

    summary = f"Enumerated {len(open_ports)} open port{'s' if len(open_ports) > 1 else ''} on {host}"
    return tool_result(
        "network.service_enum", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=summary,
        metadata={
            "ports_tested": len(port_list),
            "open_count": len(open_ports),
            "tls_ports_checked": len([p for p in open_ports if p["tls"].get("available")]),
        },
    )


tool_registry.register("network.service_enum", run, metadata={
    "name": "network.service_enum",
    "domain": "network",
    "status": "completed",
    "description": "Deep service enumeration with banner grabbing, version detection, and TLS inspection",
    "parameters": {
        "target": "Target IP or hostname",
        "ports": "Optional list of ports (default: all known service ports)",
        "timeout": "Per-port timeout (default: 2s)",
        "max_workers": "Maximum concurrent probe threads (default: 100)",
    },
})
