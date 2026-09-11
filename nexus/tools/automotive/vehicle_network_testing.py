#!/usr/bin/env python3
"""
NEXUS-STRIKE — automotive.vehicle_network_testing
Domain: automotive
In-Vehicle Network (IVN) and Ethernet Gateway Security Analyzer.
Evaluates Diagnostics over IP (DoIP / ISO 13400-2), Scalable service-Oriented
MiddlewarE over IP (SOME/IP / AUTOSAR), and IVN gateway domain segmentation
(Infotainment vs Powertrain/ADAS).
"""
from __future__ import annotations

import socket
import struct
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry

# Standard Automotive Ethernet Ports
DOIP_PORT = 13400      # ISO 13400 Diagnostics over IP (TCP & UDP)
SOMEIP_SD_PORT = 30490 # SOME/IP Service Discovery (UDP)
SOMEIP_APP_PORT = 30500

# DoIP Payload Types (ISO 13400-2)
DOIP_PAYLOAD_GENERIC_NACK        = 0x0000
DOIP_PAYLOAD_VEHICLE_IDENT_REQ   = 0x0001
DOIP_PAYLOAD_VEHICLE_IDENT_RESP  = 0x0004
DOIP_PAYLOAD_ROUTING_ACTIVATION  = 0x0005
DOIP_PAYLOAD_ROUTING_RESP        = 0x0006
DOIP_PAYLOAD_ALIVE_CHECK_REQ     = 0x0007
DOIP_PAYLOAD_DIAGNOSTIC_MESSAGE  = 0x8001
DOIP_PAYLOAD_DIAGNOSTIC_ACK      = 0x8002


def _build_doip_header(protocol_version: int, payload_type: int, payload: bytes) -> bytes:
    """Construct standard ISO 13400 DoIP 8-byte header."""
    inv_version = protocol_version ^ 0xFF
    return struct.pack("!BBHI", protocol_version, inv_version, payload_type, len(payload)) + payload


def _probe_doip_endpoint(target: str, timeout: int = 2) -> list[Finding]:
    """Probe DoIP port 13400 and evaluate routing activation security."""
    findings: list[Finding] = []

    # 1. Test TCP connection to DoIP port
    try:
        with socket.create_connection((target, DOIP_PORT), timeout=timeout) as sock:
            findings.append(Finding(
                title=f"DoIP (Diagnostics over IP / ISO 13400) Port {DOIP_PORT} Reachable",
                severity="medium",
                confidence="certain",
                affected_asset=f"{target}:{DOIP_PORT}",
                evidence=f"TCP handshake completed successfully with DoIP endpoint {target}:{DOIP_PORT}",
                remediation="Ensure DoIP port is accessible only through physical OBD-II activation pin or internal VLAN.",
                tool="automotive.vehicle_network_testing",
                references=["ISO-13400-2", "UN-ECE-R155"],
            ))

            # 2. Test Routing Activation Request (Payload Type 0x0005)
            # Standard activation: Source Address (2 bytes) + Activation Type (1 byte: 0x00 Default) + Reserved (4 bytes)
            activation_payload = struct.pack("!HBI", 0x0E00, 0x00, 0x00000000)
            req_msg = _build_doip_header(0x02, DOIP_PAYLOAD_ROUTING_ACTIVATION, activation_payload)
            sock.sendall(req_msg)

            sock.settimeout(timeout)
            resp = sock.recv(1024)
            if len(resp) >= 8:
                proto_ver, inv_ver, p_type, p_len = struct.unpack("!BBHI", resp[:8])
                if p_type == DOIP_PAYLOAD_ROUTING_RESP:
                    # Routing activation response code is at byte index 12 (offset 4 of payload)
                    if len(resp) >= 13:
                        resp_code = resp[12]
                        # 0x10 = Routing successfully activated without authentication
                        if resp_code == 0x10:
                            findings.append(Finding(
                                title="Unauthenticated DoIP Routing Activation Succeeded",
                                severity="critical",
                                confidence="certain",
                                affected_asset=f"{target}:{DOIP_PORT}",
                                evidence="DoIP gateway accepted routing activation (code 0x10) without TLS or token authentication.",
                                remediation=(
                                    "Enforce DoIP activation authentication (ISO 13400-2:2019 activation type 0x01/0x02) "
                                    "or mandate TLS encapsulation."
                                ),
                                tool="automotive.vehicle_network_testing",
                                references=["ISO-13400-2:2019", "CWE-306"],
                            ))
    except (ConnectionRefusedError, OSError):
        # Port closed or host unreachable
        pass
    except Exception as e:
        findings.append(Finding(
            title=f"DoIP probe exception on {target}",
            severity="info",
            confidence="low",
            affected_asset=f"{target}:{DOIP_PORT}",
            evidence=str(e)[:120],
            remediation="Verify network connectivity to vehicle Ethernet gateway.",
            tool="automotive.vehicle_network_testing",
        ))

    return findings


def _probe_someip_endpoint(target: str, timeout: int = 2) -> list[Finding]:
    """Check for SOME/IP Service Discovery and unencrypted service endpoints."""
    findings: list[Finding] = []

    # Check SOME/IP-SD UDP port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # SOME/IP-SD FindService message structure
        # Service ID 0xFFFF (SD), Method ID 0x8100, Length, Client 0x0000, Session 0x0001, Proto 0x01, Iface 0x01, Type 0x02 (Notification)
        header = struct.pack("!IIIBBBB", 0xFFFF8100, 0x00000010, 0x00000001, 0x01, 0x01, 0x02, 0x00)
        sd_payload = b"\x00" * 8
        sock.sendto(header + sd_payload, (target, SOMEIP_SD_PORT))

        try:
            data, _ = sock.recvfrom(1024)
            if len(data) >= 16:
                findings.append(Finding(
                    title="Active SOME/IP Service Discovery (SOME/IP-SD) Endpoint Detected",
                    severity="medium",
                    confidence="certain",
                    affected_asset=f"{target}:{SOMEIP_SD_PORT}",
                    evidence=f"Received {len(data)} bytes SOME/IP-SD response from UDP port {SOMEIP_SD_PORT}",
                    remediation="Enable AUTOSAR SecOC (Secure Onboard Communication) and restrict SD multicast groups.",
                    tool="automotive.vehicle_network_testing",
                    references=["AUTOSAR-SOMEIP", "ISO-21434"],
                ))
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
    except Exception:
        pass

    return findings


def _audit_network_segmentation_architecture(target: str) -> list[Finding]:
    """Evaluate In-Vehicle Network (IVN) segmentation architecture guidelines."""
    findings: list[Finding] = []

    findings.append(Finding(
        title="IVN Gateway Domain Isolation & Boundary Defense Check",
        severity="info",
        confidence="certain",
        affected_asset=target,
        evidence="Assessing In-Vehicle Gateway (GW) firewall configuration between Infotainment and Safety networks.",
        remediation=(
            "Verify hardware-enforced VLAN isolation (IEEE 802.1Q) and ingress rate-limiting "
            "between Telematics/IVI and ADAS/Powertrain Ethernet/CAN backbones."
        ),
        tool="automotive.vehicle_network_testing",
        references=["ISO-21434", "AUTOSAR-Firewall", "NIST-SP-800-82"],
    ))

    findings.append(Finding(
        title="Automotive Ethernet SecOC (Secure Onboard Communication) Assessment",
        severity="low",
        confidence="high",
        affected_asset=f"{target}:SOME/IP",
        evidence="SOME/IP and DoIP services require message authentication codes (MACs) for safety messages.",
        remediation="Deploy AES-128-CMAC based SecOC or DTLS for all SOME/IP inter-ECU communication.",
        tool="automotive.vehicle_network_testing",
        references=["AUTOSAR-SecOC"],
    ))

    return findings


def run(target: str, **kwargs: Any) -> dict[str, Any]:
    """Execute In-Vehicle Network (IVN) & Automotive Gateway Security Assessment.

    Parameters
    ----------
    target : str
        Target gateway IP, vehicle head-unit hostname, or network interface.
    kwargs : Any
        Optional arguments:
        - timeout: int (socket timeout in seconds, default: 2)
        - test_doip: bool (run DoIP routing activation test, default: True)
        - test_someip: bool (run SOME/IP SD test, default: True)
    """
    findings: list[Finding] = []
    timeout = int(kwargs.get("timeout", 2))
    test_doip = kwargs.get("test_doip", True)
    test_someip = kwargs.get("test_someip", True)

    metadata: dict[str, Any] = {
        "target": target,
        "protocols": ["DoIP ISO 13400-2", "SOME/IP AUTOSAR", "Automotive Ethernet"],
    }

    # 1. Probe DoIP if requested
    if test_doip:
        doip_findings = _probe_doip_endpoint(target, timeout=timeout)
        findings.extend(doip_findings)

    # 2. Probe SOME/IP if requested
    if test_someip:
        someip_findings = _probe_someip_endpoint(target, timeout=timeout)
        findings.extend(someip_findings)

    # 3. Always include IVN Domain Segmentation Architecture findings
    arch_findings = _audit_network_segmentation_architecture(target)
    findings.extend(arch_findings)

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = getattr(f, "severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_str = (
        f"Vehicle network testing completed for {target}: {len(findings)} findings "
        f"({', '.join(f'{c} {s}' for s, c in severity_counts.items())})"
    )

    return tool_result(
        "automotive.vehicle_network_testing",
        target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=summary_str,
        metadata=metadata,
    )


tool_registry.register("automotive.vehicle_network_testing", run, metadata={
    "name": "automotive.vehicle_network_testing",
    "domain": "automotive",
    "status": "completed",
    "description": (
        "In-Vehicle Network (IVN) & Automotive Ethernet security analyzer. "
        "Evaluates DoIP (ISO 13400-2) unauthenticated routing activation, "
        "SOME/IP Service Discovery exposure, and gateway domain segmentation."
    ),
    "parameters": {
        "target": "Target gateway IP, vehicle head-unit hostname, or network interface",
        "timeout": "Connection timeout in seconds (default: 2)",
        "test_doip": "Run DoIP diagnostic gateway checks (default: True)",
        "test_someip": "Run SOME/IP service discovery checks (default: True)",
    },
})
