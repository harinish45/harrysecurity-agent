#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.host_discovery
Domain: network
Host discovery via ICMP echo, TCP SYN, and ARP probing with proper Finding schema.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import subprocess
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


def _icmp_ping(host: str, timeout: float = 1.0) -> bool:
    """Send ICMP echo request to check host liveness."""
    try:
        if ":" in host:
            return _icmp_ping6(host, timeout)
        return _icmp_ping4(host, timeout)
    except Exception:
        return False


def _icmp_ping4(host: str, timeout: float) -> bool:
    """ICMP echo for IPv4 hosts."""
    try:
        import os
        if os.name == "nt":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host],
                capture_output=True,
                timeout=timeout + 1,
            )
            return result.returncode == 0
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), host],
                capture_output=True,
                timeout=timeout + 1,
            )
            return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _icmp_ping6(host: str, timeout: float) -> bool:
    """ICMP echo for IPv6 hosts."""
    try:
        result = subprocess.run(
            ["ping", "-6", "-c", "1", "-W", str(int(timeout)), host],
            capture_output=True,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _tcp_ping(host: str, port: int, timeout: float) -> bool:
    """TCP connect probe to check if a host is alive on a specific port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, OSError, ConnectionRefusedError):
        return False


def _arp_ping(host: str) -> bool:
    """Check ARP table for host presence (local network only)."""
    try:
        if "." not in host:
            return False
        addr = ipaddress.ip_address(host)
        if not addr.is_private:
            return False
        import os
        if os.name == "nt":
            result = subprocess.run(
                ["arp", "-a", host],
                capture_output=True,
                timeout=5,
            )
            return host in result.stdout.decode("utf-8", errors="replace")
        else:
            result = subprocess.run(
                ["arp", "-n", host],
                capture_output=True,
                timeout=5,
            )
            return host in result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return False


def run(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    use_arp: bool = True,
    **kwargs: Any,
) -> dict:
    """Perform host discovery against a target.

    Parameters
    ----------
    target : str
        IP address or hostname to probe.
    ports : list[int], optional
        TCP ports to probe for liveness. Defaults to common ports.
    timeout : float
        Per-probe timeout in seconds.
    use_arp : bool
        Whether to check ARP table for local hosts.
    """
    host = target.strip()
    if not host:
        return tool_result("network.host_discovery", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    discovery_methods: list[str] = []
    is_alive = False

    # Try ICMP first
    if _icmp_ping(host, timeout):
        is_alive = True
        discovery_methods.append("ICMP echo")
    else:
        # Try TCP ping on common ports
        tcp_ports = ports or [22, 80, 443, 445, 3389]
        for port in tcp_ports:
            if _tcp_ping(host, port, timeout):
                is_alive = True
                discovery_methods.append(f"TCP connect to port {port}")
                break

    # Try ARP for local hosts
    if not is_alive and use_arp:
        if _arp_ping(host):
            is_alive = True
            discovery_methods.append("ARP table entry")

    if is_alive:
        findings.append(Finding(
            title=f"Host {host} is alive",
            severity="info",
            confidence="certain",
            affected_asset=host,
            evidence=f"Host responded to: {', '.join(discovery_methods)}",
            remediation="No action needed if host is authorized.",
            tool="network.host_discovery",
        ))

        # Try to resolve hostname
        try:
            hostname = socket.gethostbyaddr(host)[0]
            if hostname != host:
                findings.append(Finding(
                    title=f"Hostname resolution for {host}",
                    severity="info",
                    confidence="certain",
                    affected_asset=host,
                    evidence=f"Reverse DNS: {host} -> {hostname}",
                    remediation="Verify hostname is expected for this asset.",
                    tool="network.host_discovery",
                ))
        except (socket.herror, socket.gaierror):
            pass

        return tool_result(
            "network.host_discovery", target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Host {host} is alive (discovered via: {', '.join(discovery_methods)})",
            metadata={"discovery_methods": discovery_methods, "alive": True},
        )

    return tool_result(
        "network.host_discovery", target,
        status=STATUS_NO_FINDINGS,
        summary=f"Host {host} appears to be down or not responding",
        metadata={"alive": False},
    )


tool_registry.register("network.host_discovery", run, metadata={
    "name": "network.host_discovery",
    "domain": "network",
    "status": "completed",
    "description": "Host discovery via ICMP echo, TCP SYN, and ARP probing",
    "parameters": {
        "target": "Target IP or hostname",
        "ports": "TCP ports to probe for liveness (default: 22,80,443,445,3389)",
        "timeout": "Per-probe timeout in seconds (default: 1s)",
        "use_arp": "Check ARP table for local hosts (default: True)",
    },
})
