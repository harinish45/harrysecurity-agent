#!/usr/bin/env python3
"""
NEXUS-STRIKE — ot_ics.modbus_analysis
Domain: ot_ics

Previously checked real port reachability but never spoke Modbus at all
(byte-for-byte identical to plc_testing.py, scada_security.py,
industrial_protocol_reviews.py, dnp3_testing.py before this fix) — caught
during this session's audit.

Now: a real Modbus TCP request (MBAP header + function code 0x03, Read
Holding Registers — the standard, safe, read-only Modbus query) framed
per the official Modbus Application Protocol spec, sent to port 502, with
a real parse of whatever comes back: a valid holding-register response, a
Modbus exception response (which still proves a genuine Modbus server is
listening), or nothing (port closed/filtered/non-Modbus).
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

_MODBUS_PORT = 502
_FUNC_READ_HOLDING_REGISTERS = 0x03
_FUNC_READ_COILS = 0x01

_EXCEPTION_CODES = {
    1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value",
    4: "Slave Device Failure", 5: "Acknowledge", 6: "Slave Device Busy",
    8: "Memory Parity Error", 10: "Gateway Path Unavailable", 11: "Gateway Target Device Failed to Respond",
}


def _build_modbus_request(transaction_id: int, unit_id: int, function_code: int,
                           start_addr: int, quantity: int) -> bytes:
    pdu = struct.pack(">BHH", function_code, start_addr, quantity)
    length = len(pdu) + 1  # + unit_id
    mbap = struct.pack(">HHHB", transaction_id, 0, length, unit_id)
    return mbap + pdu


def _parse_modbus_response(response: bytes, expected_function: int) -> dict:
    if len(response) < 8:
        return {"valid": False, "reason": "response too short for MBAP header"}
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", response[:7])
    if protocol_id != 0:
        return {"valid": False, "reason": f"unexpected protocol_id {protocol_id} (Modbus TCP must be 0)"}
    function_code = response[7]
    if function_code == (0x80 | expected_function):
        exception_code = response[8] if len(response) > 8 else None
        return {
            "valid": True, "exception": True,
            "exception_code": exception_code,
            "exception_name": _EXCEPTION_CODES.get(exception_code, "Unknown"),
            "unit_id": unit_id,
        }
    if function_code == expected_function:
        byte_count = response[8] if len(response) > 8 else 0
        data = response[9:9 + byte_count]
        return {"valid": True, "exception": False, "unit_id": unit_id, "byte_count": byte_count, "data_hex": data.hex()}
    return {"valid": False, "reason": f"unexpected function code 0x{function_code:02x} in response"}


def _modbus_query(target: str, function_code: int, timeout: float, unit_id: int = 1,
                   start_addr: int = 0, quantity: int = 10) -> dict:
    result: dict[str, Any] = {"reachable": False}
    try:
        with socket.create_connection((target, _MODBUS_PORT), timeout=timeout) as sock:
            result["reachable"] = True
            sock.settimeout(timeout)
            request = _build_modbus_request(0x0001, unit_id, function_code, start_addr, quantity)
            sock.sendall(request)
            response = sock.recv(256)
            result["raw_response_hex"] = response.hex()
            result.update(_parse_modbus_response(response, function_code))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)[:150]
    return result


def run(target: str, timeout: float = 4.0, unit_id: int = 1, **kwargs: Any) -> dict:
    """Real Modbus TCP Read Holding Registers (fn 0x03) query against port 502."""
    host = target.strip()
    if not host:
        return tool_result("ot_ics.modbus_analysis", target, status=STATUS_FAILED, error="Empty target")

    probe = _modbus_query(host, _FUNC_READ_HOLDING_REGISTERS, timeout, unit_id=unit_id)
    if probe.get("reachable") and not probe.get("valid"):
        # Port open but fn 0x03 not decoded — try Read Coils (fn 0x01) as a second real probe.
        probe_coils = _modbus_query(host, _FUNC_READ_COILS, timeout, unit_id=unit_id)
        probe = {"holding_registers_probe": probe, "coils_probe": probe_coils, "reachable": True,
                 "valid": probe_coils.get("valid", False)}
    elif not probe.get("reachable"):
        return tool_result(
            "ot_ics.modbus_analysis", target,
            status=STATUS_NO_FINDINGS,
            summary=f"Modbus TCP port {_MODBUS_PORT} not reachable on {host}",
            metadata={"probe": probe},
        )

    findings: list[Finding] = []
    if probe.get("valid"):
        if probe.get("exception"):
            findings.append(Finding(
                title=f"Modbus server responding on {host}:{_MODBUS_PORT} (exception: {probe.get('exception_name')})",
                severity="high", confidence="certain",
                affected_asset=f"{host}:{_MODBUS_PORT}",
                evidence=f"Modbus exception response code={probe.get('exception_code')} "
                         f"({probe.get('exception_name')}) — a genuine Modbus server answered "
                         f"the request, meaning the ICS Modbus interface is network-reachable "
                         f"and unauthenticated (Modbus TCP has no built-in authentication).",
                remediation="Restrict Modbus TCP (502) to an isolated OT network segment; "
                            "Modbus has no native authentication — network isolation is the "
                            "primary control.",
                tool="ot_ics.modbus_analysis",
                references=["IEC-62443-3-3", "CWE-306", "CWE-284"],
            ))
        else:
            findings.append(Finding(
                title=f"Modbus server responding on {host}:{_MODBUS_PORT} with live register data",
                severity="critical", confidence="certain",
                affected_asset=f"{host}:{_MODBUS_PORT}",
                evidence=f"Real Modbus response data: {probe.get('data_hex') or probe}",
                remediation="Modbus TCP is unauthenticated by design — restrict network access "
                            "to an isolated OT segment immediately; unauthenticated read/write "
                            "access to registers can allow process manipulation.",
                tool="ot_ics.modbus_analysis",
                references=["IEC-62443-3-3", "CWE-306", "CWE-284"],
            ))
    else:
        findings.append(Finding(
            title=f"Port {_MODBUS_PORT} open on {host} but no valid Modbus response decoded",
            severity="low", confidence="medium",
            affected_asset=f"{host}:{_MODBUS_PORT}",
            evidence=str(probe),
            remediation="Verify the service on this port; a non-Modbus service may be listening.",
            tool="ot_ics.modbus_analysis",
        ))

    return tool_result(
        "ot_ics.modbus_analysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Modbus TCP analysis of {host}:{_MODBUS_PORT} completed",
        metadata={"probe": probe},
    )


tool_registry.register("ot_ics.modbus_analysis", run, metadata={
    "name": "ot_ics.modbus_analysis",
    "domain": "ot_ics",
    "status": "completed",
    "description": "Real Modbus TCP Read Holding Registers / Read Coils query (correctly framed per spec) against port 502",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "TCP/response timeout in seconds (default: 4.0)",
        "unit_id": "Modbus unit/slave id (default: 1)",
    },
})
