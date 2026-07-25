# -*- coding: utf-8 -*-
"""
NEXUS-STRIKE — network.port_scan
Domain: network
Robust TCP port scanning with service fingerprinting, TLS inspection, and safe defaults.
"""
from __future__ import annotations

import concurrent.futures
import socket
import ssl
import struct
import time
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

# Well-known port → service mapping
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

COMMON_PORTS = sorted(KNOWN_SERVICES.keys())


def _probe_port(host: str, port: int, timeout: float = 2.0) -> dict:
    """Probe a single TCP port. Returns port info or None."""
    family = socket.AF_INET
    # Try IPv6 if host looks like one
    if ":" in host:
        family = socket.AF_INET6
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Attempt banner grab
            banner = _grab_banner(sock, port)
            # Attempt TLS detection for common TLS ports
            tls = _check_tls(host, port, timeout)
            return {
                "port": port,
                "state": "open",
                "service": KNOWN_SERVICES.get(port, "unknown"),
                "banner": banner or "",
                "tls": tls,
            }
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass
    return None


def _grab_banner(sock: socket.socket, port: int, max_bytes: int = 4096) -> str:
    """Grab a service banner from an open socket."""
    try:
        # Send a minimal probe for some services
        if port in (21, 25, 110, 143, 220, 993, 995):  # Plaintext protocols
            sock.sendall(b"\r\n")
        elif port in (80, 8080, 8000, 443, 8443):
            sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        data = sock.recv(max_bytes)
        return data.decode("utf-8", errors="replace").strip()[:512]
    except OSError:
        return ""


def _check_tls(host: str, port: int, timeout: float) -> dict:
    """Attempt TLS handshake and return certificate info."""
    if port not in (443, 8443, 993, 995, 465, 636, 989, 990, 587):
        # Only attempt on ports that commonly use TLS
        return {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=True)
                if not cert:
                    return {"available": True, "cert": None}
                # Basic TLS info
                version = tls_sock.version()
                cipher = tls_sock.cipher()
                return {
                    "available": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[1] if cipher else 0,
                }
    except Exception:
        return {"available": False}


def run(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    max_workers: int = 100,
    **kwargs: Any,
) -> dict:
    """Perform TCP port scanning against target with service fingerprinting.

    Parameters
    ----------
    target : str
        IP address or hostname to scan.
    ports : list[int], optional
        Port list. Defaults to all known service ports.
    timeout : float
        Per-port connection timeout in seconds.
    max_workers : int
        Maximum concurrent probe threads.
    """
    host = target.strip()
    if not host:
        return tool_result("network.port_scan", target, status=STATUS_FAILED, error="Empty target")

    port_list = ports or COMMON_PORTS
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
            "network.port_scan", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No open ports found on {host} among {len(port_list)} tested ports",
        )

    # Generate findings
    for p in open_ports:
        sev = "high" if p["service"] in ("SSH", "Telnet", "FTP", "RDP", "VNC", "SMB") else \
              "medium" if p["service"] in ("HTTP", "MySQL", "MSSQL", "Redis", "MongoDB", "Elasticsearch") else \
              "low"
        evidence = f"Port {p['port']}/{p['service']} open"
        if p.get("banner"):
            evidence += f"\nBanner: {p['banner'][:200]}"
        if p.get("tls", {}).get("available"):
            tls = p["tls"]
            evidence += f"\nTLS: version={tls.get('version')} cipher={tls.get('cipher')}"
            if tls.get("version", "").startswith("TLSv1.0") or tls.get("version", "").startswith("TLSv1.1"):
                sev = "high"

        remediation = f"Review open port {p['port']} ({p['service']}). Close if not required."
        if p["service"] in ("Telnet", "FTP"):
            remediation = f"Replace {p['service']} with secure alternatives (SSH/SFTP)."
        elif p["service"] in ("Redis", "MongoDB", "Elasticsearch"):
            remediation = f"Ensure {p['service']} is bound to localhost and requires authentication."

        findings.append(Finding(
            title=f"Open port {p['port']} ({p['service']}) on {host}",
            severity=sev,
            confidence="certain",
            affected_asset=f"{host}:{p['port']}",
            evidence=evidence,
            remediation=remediation,
            tool="network.port_scan",
        ))

    summary = f"Found {len(open_ports)} open port{'s' if len(open_ports) > 1 else ''} on {host}"
    return tool_result(
        "network.port_scan", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=summary,
        metadata={
            "ports_tested": len(port_list),
            "open_count": len(open_ports),
        },
    )


tool_registry.register("network.port_scan", run, metadata={
    "name": "network.port_scan",
    "domain": "network",
    "status": "completed",
    "description": "TCP port scan with service fingerprinting and TLS inspection",
    "parameters": {
        "target": "Target IP or hostname",
        "ports": "Optional list of ports (default: all known service ports)",
        "timeout": "Per-port timeout (default: 2s)",
    },
})