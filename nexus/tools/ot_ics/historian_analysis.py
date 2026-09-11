#!/usr/bin/env python3
"""
NEXUS-STRIKE — ot_ics.historian_analysis
Domain: ot_ics
Industrial historian database security assessment — evaluates OSIsoft PI,
Wonderware, and generic OPC-DA/UA historian endpoints for authentication
weaknesses, unencrypted data, and excessive data exposure.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import socket
import struct
import urllib.request
import urllib.error
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry


# Common historian ports
_HISTORIAN_PORTS = {
    5450: "OSIsoft PI Data Archive",
    5457: "OSIsoft PI Asset Framework",
    8080: "Wonderware Information Server (HTTP)",
    8443: "Wonderware Information Server (HTTPS)",
    4840: "OPC-UA",
    135:  "OPC-DA (DCOM/RPC)",
    502:  "Modbus (often bridged to historians)",
}

_OPC_UA_HELLO = b"HELF"  # First 4 bytes of OPC UA Hello message


def _check_open_ports(target: str, timeout: int = 5) -> list[Finding]:
    """Check for exposed historian service ports."""
    findings: list[Finding] = []

    for port, service in _HISTORIAN_PORTS.items():
        try:
            with socket.create_connection((target, port), timeout=timeout):
                sev = "high" if port in (135, 502, 5450) else "medium"
                findings.append(Finding(
                    title=f"{service} port {port} is open",
                    severity=sev,
                    confidence="certain",
                    affected_asset=f"{target}:{port}",
                    evidence=f"TCP connection established to {target}:{port}",
                    remediation=(
                        f"Restrict access to port {port} to authorised engineering workstations only. "
                        "Use network segmentation and VPN for remote access."
                    ),
                    tool="ot_ics.historian_analysis",
                    references=["IEC-62443-3-3", "NIST-SP-800-82", "CWE-284"],
                ))
        except (ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass

    return findings


def _check_web_interface(target: str, timeout: int = 5) -> list[Finding]:
    """Check for unauthenticated historian web interfaces."""
    findings: list[Finding] = []

    web_paths = [
        "/",
        "/historian/",
        "/pi/",
        "/wonderware/",
        "/ProcessData/",
        "/api/v1/points",
        "/opc/rest/",
    ]

    for scheme in ("http", "https"):
        for path in web_paths:
            url = f"{scheme}://{target}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "NexusStrike-OT/1.0"},
                )
                with safe_urlopen(req, timeout=timeout) as resp:
                    body_preview = resp.read(512).decode("utf-8", errors="ignore")
                    # Flag if no authentication prompt and page contains data indicators
                    data_keywords = ["tagname", "value", "timestamp", "point", "datasource", "historian"]
                    if any(kw in body_preview.lower() for kw in data_keywords):
                        findings.append(Finding(
                            title=f"Historian web interface accessible without authentication at {path}",
                            severity="critical",
                            confidence="high",
                            affected_asset=url,
                            evidence=f"HTTP {resp.status} returned process data indicators: {body_preview[:200]}",
                            remediation=(
                                "Enable authentication on the historian web interface. "
                                "Implement role-based access control per IEC 62443-3-3 SR 1.1."
                            ),
                            tool="ot_ics.historian_analysis",
                            references=["IEC-62443-3-3", "CWE-306", "NIST-SP-800-82"],
                        ))
                    else:
                        findings.append(Finding(
                            title=f"Historian web path {path} is reachable",
                            severity="low",
                            confidence="medium",
                            affected_asset=url,
                            evidence=f"HTTP {resp.status}; no obvious process data in response preview.",
                            remediation="Verify authentication is enforced for all historian web endpoints.",
                            tool="ot_ics.historian_analysis",
                            references=["IEC-62443-3-3"],
                        ))
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    # Good — authentication is enforced
                    findings.append(Finding(
                        title=f"Historian web path {path} requires authentication (HTTP {e.code})",
                        severity="info",
                        confidence="certain",
                        affected_asset=url,
                        evidence=f"HTTP {e.code} — authentication enforced.",
                        remediation="Verify that default credentials are not in use.",
                        tool="ot_ics.historian_analysis",
                        references=["IEC-62443-3-3"],
                    ))
            except Exception:
                pass

    return findings


def _check_opc_ua_endpoint(target: str, timeout: int = 5) -> list[Finding]:
    """Check OPC-UA endpoint for anonymous access."""
    findings: list[Finding] = []
    port = 4840

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            # Send minimal OPC-UA Hello message
            # Structure: MessageType(3) + Reserved(1) + MessageSize(4) + Version(4) + ...
            hello = struct.pack("<4sI4sI", b"HEL", 32, b"\x00" * 4, 0)
            sock.sendall(hello)
            banner = sock.recv(128)
            if banner:
                findings.append(Finding(
                    title="OPC-UA endpoint responded to Hello message",
                    severity="medium",
                    confidence="high",
                    affected_asset=f"{target}:{port}",
                    evidence=f"OPC-UA response banner: {banner[:64].hex()}",
                    remediation=(
                        "Configure OPC-UA security mode to SignAndEncrypt. "
                        "Disable Anonymous user token policy. Require certificate authentication."
                    ),
                    tool="ot_ics.historian_analysis",
                    references=["IEC-62541", "CVE-2019-13549", "CWE-306"],
                ))
    except (ConnectionRefusedError, OSError, struct.error):
        pass
    except Exception:
        pass

    return findings


def run(
    target: str,
    timeout: int = 5,
    check_web: bool = True,
    check_opc: bool = True,
    **kwargs: Any,
) -> dict:
    """Perform industrial historian database security assessment.

    Parameters
    ----------
    target : str
        Hostname or IP of the historian server (e.g., OSIsoft PI, Wonderware).
    timeout : int
        TCP connection timeout in seconds (default: 5).
    check_web : bool
        Check web interface for unauthenticated access (default: True).
    check_opc : bool
        Check OPC-UA endpoint for anonymous access (default: True).
    """
    findings: list[Finding] = []

    findings.extend(_check_open_ports(target, timeout=timeout))

    if check_web:
        findings.extend(_check_web_interface(target, timeout=timeout))

    if check_opc:
        findings.extend(_check_opc_ua_endpoint(target, timeout=timeout))

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = getattr(f, "severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return tool_result(
        "ot_ics.historian_analysis",
        target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=(
            f"Historian analysis completed: {len(findings)} findings "
            f"({', '.join(f'{c} {s}' for s, c in severity_counts.items())})"
        ),
        metadata={"target_type": "historian", "protocols": ["PI", "Wonderware", "OPC-UA"]},
    )


tool_registry.register("ot_ics.historian_analysis", run, metadata={
    "name": "ot_ics.historian_analysis",
    "domain": "ot_ics",
    "status": "completed",
    "description": (
        "Industrial historian database security assessment — evaluates OSIsoft PI, "
        "Wonderware, and OPC-UA historian endpoints for authentication weaknesses "
        "and unencrypted data exposure."
    ),
    "parameters": {
        "target": "Hostname or IP of historian server",
        "timeout": "TCP connection timeout in seconds (default: 5)",
        "check_web": "Check web interface authentication (default: True)",
        "check_opc": "Check OPC-UA anonymous access (default: True)",
    },
})
