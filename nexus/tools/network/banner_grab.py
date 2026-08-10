#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.banner_grab
Domain: network
Banner grabbing and service version detection from open TCP ports.
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
    tool_result,
)
from nexus.tools.registry import tool_registry

BANNER_PROBES: dict[int, bytes] = {
    21: b"SYST\r\n",
    22: b"\r\n",
    25: b"EHLO localhost\r\n",
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
    587: "SMTP-Submit", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "OracleDB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}

TLS_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 587}


def _grab_banner(host: str, port: int, timeout: float = 2.0, max_bytes: int = 4096) -> Optional[str]:
    """Grab a banner from an open TCP port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            probe = BANNER_PROBES.get(port, b"")
            if probe:
                sock.sendall(probe)
            data = sock.recv(max_bytes)
            return data.decode("utf-8", errors="replace").strip()[:512]
    except (socket.timeout, OSError, ConnectionRefusedError):
        return None


def _check_tls(host: str, port: int, timeout: float) -> Optional[dict]:
    """Check TLS configuration on a port."""
    if port not in TLS_PORTS:
        return None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
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


def _parse_banner_version(banner: str, port: int) -> dict:
    """Parse version information from a banner string."""
    info = {"raw": banner, "version": "", "product": ""}
    if not banner:
        return info

    service = KNOWN_SERVICES.get(port, "unknown")

    if service == "SSH" or "SSH-" in banner:
        if "SSH-" in banner:
            parts = banner.split("SSH-")[1].split("-")
            if len(parts) >= 2:
                info["product"] = parts[0]
                info["version"] = parts[1]
    elif service == "HTTP" or "HTTP/" in banner:
        for line in banner.split("\n"):
            if "Server:" in line:
                info["product"] = line.split("Server:")[1].strip().split()[0]
    elif service == "FTP":
        if banner.startswith("220"):
            info["product"] = banner[4:].split()[0]
    elif service == "SMTP":
        if banner.startswith("220"):
            info["product"] = banner[4:].split()[0]
    elif service == "MySQL":
        if banner.startswith("5"):
            info["product"] = "MySQL"
            info["version"] = banner[:6]

    return info


def run(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    max_workers: int = 50,
    **kwargs: Any,
) -> dict:
    """Grab banners from open TCP ports and detect service versions.

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
    import concurrent.futures

    host = target.strip()
    if not host:
        return tool_result("network.banner_grab", target, status=STATUS_FAILED, error="Empty target")

    port_list = ports or sorted(KNOWN_SERVICES.keys())
    findings: list[Finding] = []
    banners: list[dict] = []

    def _probe(port: int) -> Optional[dict]:
        banner = _grab_banner(host, port, timeout)
        if banner:
            tls = _check_tls(host, port, timeout)
            version_info = _parse_banner_version(banner, port)
            return {
                "port": port,
                "service": KNOWN_SERVICES.get(port, "unknown"),
                "banner": banner,
                "version_info": version_info,
                "tls": tls,
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        fut_map = {executor.submit(_probe, p): p for p in port_list}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                result = fut.result()
                if result:
                    banners.append(result)
            except Exception:
                pass

    banners.sort(key=lambda x: x["port"])

    if not banners:
        return tool_result(
            "network.banner_grab", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No banners retrieved from {host} among {len(port_list)} tested ports",
        )

    for b in banners:
        vi = b.get("version_info", {})
        evidence_parts = [f"Port {b['port']}/{b['service']}"]
        if vi.get("product"):
            evidence_parts.append(f"Product: {vi['product']}")
        if vi.get("version"):
            evidence_parts.append(f"Version: {vi['version']}")
        evidence_parts.append(f"Banner: {b['banner'][:200]}")
        if b.get("tls") and b["tls"].get("available"):
            tls = b["tls"]
            evidence_parts.append(f"TLS: {tls.get('version')} cipher={tls.get('cipher')}")
            if tls.get("not_after"):
                evidence_parts.append(f"Cert expires: {tls['not_after']}")

        evidence = "\n".join(evidence_parts)

        sev = "medium"
        if b["service"] in ("SSH", "Telnet", "FTP", "RDP", "VNC"):
            sev = "high"
        if b.get("tls") and b["tls"].get("version", "").startswith(("TLSv1.0", "TLSv1.1", "SSL")):
            sev = "high"

        remediation = f"Review service on port {b['port']} ({b['service']})."
        if b["service"] in ("Telnet", "FTP"):
            remediation = f"Replace {b['service']} with secure alternatives (SSH/SFTP)."
        elif b["service"] in ("Redis", "MongoDB"):
            remediation = f"Ensure {b['service']} requires authentication and is not exposed."

        findings.append(Finding(
            title=f"Service banner on port {b['port']} ({b['service']})",
            severity=sev,
            confidence="certain",
            affected_asset=f"{host}:{b['port']}",
            evidence=evidence,
            remediation=remediation,
            tool="network.banner_grab",
            references=["CWE-200", "CWE-209"],
        ))

    summary = f"Retrieved {len(banners)} banner{'s' if len(banners) > 1 else ''} from {host}"
    return tool_result(
        "network.banner_grab", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=summary,
        metadata={
            "ports_scanned": len(port_list),
            "banners_found": len(banners),
            "tls_ports": len([b for b in banners if b.get("tls") and b["tls"].get("available")]),
        },
    )


tool_registry.register("network.banner_grab", run, metadata={
    "name": "network.banner_grab",
    "domain": "network",
    "status": "completed",
    "description": "Banner grabbing and service version detection from open TCP ports",
    "parameters": {
        "target": "Target IP or hostname",
        "ports": "Optional list of ports (default: all known service ports)",
        "timeout": "Per-port timeout (default: 2s)",
        "max_workers": "Maximum concurrent probe threads (default: 50)",
    },
})
