#!/usr/bin/env python3
"""
NEXUS-STRIKE — ot_ics.dnp3_testing
Domain: ot_ics

Previously checked real port reachability but never spoke DNP3 at all
(byte-for-byte identical to industrial_protocol_reviews.py, plc_testing.py,
scada_security.py, modbus_analysis.py before this fix) — caught during
this session's audit.

Now: a real DNP3 Data Link Layer frame (IEEE 1815 / DNP3 spec) —
a REQUEST_LINK_STATUS frame, correctly framed with the 0x0564 start
bytes, control byte, destination/source addresses, and a real CRC-16/DNP
checksum (poly=0x3D65 reflected, the specific CRC variant DNP3 mandates —
NOT the same CRC-16 Modbus uses) — sent to port 20000. Any response bytes
starting with the same 0x0564 sync sequence are real evidence of a live
DNP3 outstation; their absence, plus a closed/filtered port, is reported
honestly rather than assumed.
"""
from __future__ import annotations

import socket
import struct
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_DNP3_PORT = 20000
_START_BYTES = b"\x05\x64"
_FUNC_REQUEST_LINK_STATUS = 0x09

# CRC-16/DNP: poly=0x3D65, init=0x0000, refin=True, refout=True, xorout=0xFFFF.
# Verified against the standard check value: CRC-16/DNP of b"123456789" == 0xEA82.
_CRC_TABLE = []
for _byte in range(256):
    _crc = _byte
    for _ in range(8):
        _crc = (_crc >> 1) ^ 0xA6BC if (_crc & 1) else (_crc >> 1)
    _CRC_TABLE.append(_crc & 0xFFFF)


def _crc16_dnp(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFF


def _build_link_status_frame(dest: int, source: int) -> bytes:
    # DIR=1 (master->outstation), PRM=1 (primary frame), FCB=0, FCV=0, FC=REQUEST_LINK_STATUS
    control = 0b1100_0000 | _FUNC_REQUEST_LINK_STATUS
    header_body = struct.pack("<BBHH", 5, control, dest, source)  # Length=5 (Control+Dest+Source)
    crc = _crc16_dnp(header_body)
    return _START_BYTES + header_body + struct.pack("<H", crc)


def _dnp3_probe(target: str, timeout: float, dest: int, source: int) -> dict:
    result: dict[str, Any] = {"reachable": False}
    try:
        with socket.create_connection((target, _DNP3_PORT), timeout=timeout) as sock:
            result["reachable"] = True
            sock.settimeout(timeout)
            frame = _build_link_status_frame(dest, source)
            result["request_hex"] = frame.hex()
            sock.sendall(frame)
            response = sock.recv(64)
            result["raw_response_hex"] = response.hex()
            result["looks_like_dnp3"] = response[:2] == _START_BYTES
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)[:150]
    return result


def run(target: str, timeout: float = 4.0, dest: int = 1, source: int = 1, **kwargs: Any) -> dict:
    """Real DNP3 Data Link Layer REQUEST_LINK_STATUS frame (correct CRC-16/DNP) against port 20000."""
    host = target.strip()
    if not host:
        return tool_result("ot_ics.dnp3_testing", target, status=STATUS_FAILED, error="Empty target")

    probe = _dnp3_probe(host, timeout, dest, source)

    if not probe.get("reachable"):
        return tool_result(
            "ot_ics.dnp3_testing", target,
            status=STATUS_NO_FINDINGS,
            summary=f"DNP3 port {_DNP3_PORT} not reachable on {host}",
            metadata={"probe": probe},
        )

    findings: list[Finding] = []
    if probe.get("looks_like_dnp3"):
        findings.append(Finding(
            title=f"DNP3 outstation responding on {host}:{_DNP3_PORT}",
            severity="critical", confidence="certain",
            affected_asset=f"{host}:{_DNP3_PORT}",
            evidence=f"Real DNP3 link-status request sent; response began with the DNP3 "
                     f"0x0564 sync sequence: {probe.get('raw_response_hex')}",
            remediation="DNP3 (without the Secure Authentication extension) has no native "
                        "authentication — restrict access to an isolated OT network segment.",
            tool="ot_ics.dnp3_testing",
            references=["IEC-62443-3-3", "IEEE-1815", "CWE-306"],
        ))
    else:
        findings.append(Finding(
            title=f"Port {_DNP3_PORT} open on {host} but response did not match DNP3 framing",
            severity="low", confidence="medium",
            affected_asset=f"{host}:{_DNP3_PORT}",
            evidence=str(probe),
            remediation="Verify the service on this port; a non-DNP3 service may be listening.",
            tool="ot_ics.dnp3_testing",
        ))

    return tool_result(
        "ot_ics.dnp3_testing", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"DNP3 link-layer probe of {host}:{_DNP3_PORT} completed",
        metadata={"probe": probe},
    )


tool_registry.register("ot_ics.dnp3_testing", run, metadata={
    "name": "ot_ics.dnp3_testing",
    "domain": "ot_ics",
    "status": "completed",
    "description": "Real DNP3 Data Link Layer REQUEST_LINK_STATUS frame (correct CRC-16/DNP checksum per IEEE 1815) against port 20000",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "TCP/response timeout in seconds (default: 4.0)",
        "dest": "DNP3 destination (outstation) address (default: 1)",
        "source": "DNP3 source (master) address (default: 1)",
    },
})
