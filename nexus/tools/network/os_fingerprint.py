#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.os_fingerprint
Domain: network
Passive and active OS fingerprinting via TCP/IP stack characteristics.
"""
from __future__ import annotations

import socket
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
from nexus.tools.sandbox import run_subprocess, SandboxError


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> Optional[dict]:
    """Send TCP SYN and analyze the response for OS fingerprinting."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Build IP header
            ip_ihl = 5
            ip_ver = 4
            ip_ver_ihl = (ip_ver << 4) + ip_ihl
            ip_tos = 0
            ip_tot_len = 40
            ip_id = 54321
            ip_frag_off = 0
            ip_ttl = 64
            ip_proto = socket.IPPROTO_TCP
            ip_check = 0
            ip_src = "0.0.0.0"
            ip_dst = host

            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                ip_ttl, ip_proto, ip_check,
                socket.inet_aton(ip_src), socket.inet_aton(ip_dst),
            )

            # Build TCP SYN header
            tcp_src_port = 54321
            tcp_dst_port = port
            tcp_seq = 12345
            tcp_ack_seq = 0
            tcp_doff = 5
            tcp_flags = 0x02  # SYN
            tcp_window = 65535
            tcp_check = 0
            tcp_urg = 0

            tcp_offset_res = (tcp_doff << 4)
            tcp_header = struct.pack(
                "!HHLLBBHHH",
                tcp_src_port, tcp_dst_port,
                tcp_seq, tcp_ack_seq,
                tcp_offset_res, tcp_flags,
                tcp_window, tcp_check, tcp_urg,
            )

            packet = ip_header + tcp_header
            sock.sendto(packet, (host, 0))

            try:
                data, addr = sock.recvfrom(4096)
                if data:
                    ip_header = data[0:20]
                    ip_ver = ip_header[0] >> 4
                    if ip_ver == 4:
                        ip_ttl = ip_header[5]
                        tcp_header = data[20:40]
                        tcp_flags = tcp_header[13]
                        tcp_window = struct.unpack("!H", tcp_header[14:16])[0]
                        return {
                            "ttl": ip_ttl,
                            "tcp_flags": tcp_flags,
                            "window_size": tcp_window,
                        }
            except socket.timeout:
                pass
    except (PermissionError, OSError):
        pass
    return None


def _nmap_os_detection(host: str, timeout: int = 30) -> Optional[list[dict]]:
    """Use nmap OS detection if available."""
    try:
        result = run_subprocess(
            ["nmap", "-O", "--host-timeout", f"{timeout}s", "-Pn", host],
            timeout=timeout + 5,
        )
        if result.returncode == 0:
            output = result.stdout
            os_matches = []
            for line in output.split("\n"):
                if "OS details" in line or "Running:" in line:
                    os_matches.append({"raw": line.strip()})
            return os_matches if os_matches else None
    except (FileNotFoundError, SandboxError):
        pass
    return None


def _passive_fingerprint(host: str) -> Optional[dict]:
    """Attempt passive OS fingerprinting via TCP connection characteristics."""
    results = {}
    for port in [22, 80, 443]:
        try:
            with socket.create_connection((host, port), timeout=2) as sock:
                sock.settimeout(2)
                # Check if the port sends a banner immediately
                try:
                    banner = sock.recv(1024)
                    if banner:
                        results[port] = {"banner": banner.decode("utf-8", errors="replace").strip()[:200]}
                except socket.timeout:
                    results[port] = {"no_banner": True}
        except (socket.timeout, OSError, ConnectionRefusedError):
            pass
    return results if results else None


def _classify_os_by_ttl(ttl: int) -> str:
    """Classify OS by TTL value."""
    if ttl == 64:
        return "Linux/Unix (TTL=64)"
    elif ttl == 128:
        return "Windows (TTL=128)"
    elif ttl == 255:
        return "macOS/BSD (TTL=255)"
    elif ttl == 60:
        return "Windows (TTL=60)"
    else:
        return f"Unknown (TTL={ttl})"


def run(
    target: str,
    timeout: float = 2.0,
    use_nmap: bool = True,
    **kwargs: Any,
) -> dict:
    """Perform OS fingerprinting against a target.

    Parameters
    ----------
    target : str
        IP address or hostname to fingerprint.
    timeout : float
        Per-probe timeout in seconds.
    use_nmap : bool
        Whether to use nmap for OS detection if available.
    """
    host = target.strip()
    if not host:
        return tool_result("network.os_fingerprint", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    fingerprint_data: list[dict] = []

    # Try nmap first if available
    if use_nmap:
        nmap_result = _nmap_os_detection(host, int(timeout * 10))
        if nmap_result:
            for match in nmap_result:
                findings.append(Finding(
                    title=f"OS detection result for {host}",
                    severity="info",
                    confidence="high",
                    affected_asset=host,
                    evidence=match.get("raw", ""),
                    remediation="Verify OS identity through authorized means.",
                    tool="network.os_fingerprint",
                    references=["CWE-200"],
                ))
                fingerprint_data.append(match)

    # Try TCP SYN probing for TTL-based fingerprinting
    for port in [22, 80, 443, 445, 3389]:
        result = _tcp_probe(host, port, timeout)
        if result:
            ttl = result.get("ttl", 0)
            os_guess = _classify_os_by_ttl(ttl)
            findings.append(Finding(
                title=f"OS fingerprint via TCP SYN on port {port}",
                severity="info",
                confidence="medium",
                affected_asset=f"{host}:{port}",
                evidence=f"TTL={ttl}, Window={result.get('window_size')}, TCP Flags=0x{result.get('tcp_flags', 0):02x}",
                remediation="Confirm OS identity through authorized asset inventory.",
                tool="network.os_fingerprint",
                references=["CWE-200"],
            ))
            fingerprint_data.append({"port": port, "ttl": ttl, "os_guess": os_guess})
            break

    # Try passive fingerprinting
    passive = _passive_fingerprint(host)
    if passive:
        for port, data in passive.items():
            if data.get("banner"):
                findings.append(Finding(
                    title=f"Banner-based fingerprint on port {port}",
                    severity="info",
                    confidence="medium",
                    affected_asset=f"{host}:{port}",
                    evidence=f"Banner: {data['banner'][:200]}",
                    remediation="Identify service version and associated OS.",
                    tool="network.os_fingerprint",
                ))

    if not findings:
        return tool_result(
            "network.os_fingerprint", target,
            status=STATUS_NO_FINDINGS,
            summary=f"Could not determine OS for {host}",
            metadata={"fingerprint_data": fingerprint_data},
        )

    return tool_result(
        "network.os_fingerprint", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"OS fingerprinting completed for {host} using {len(findings)} methods",
        metadata={"fingerprint_data": fingerprint_data},
    )


tool_registry.register("network.os_fingerprint", run, metadata={
    "name": "network.os_fingerprint",
    "domain": "network",
    "status": "completed",
    "description": "OS fingerprinting via TCP/IP stack characteristics and nmap",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "Per-probe timeout in seconds (default: 2s)",
        "use_nmap": "Use nmap for OS detection if available (default: True)",
    },
})
