#!/usr/bin/env python3
"""
NEXUS-STRIKE — ot_ics.plc_testing
Domain: ot_ics

Previously checked real port reachability but never spoke any PLC
protocol at all (byte-for-byte identical to industrial_protocol_reviews.py,
scada_security.py, modbus_analysis.py, dnp3_testing.py before this fix)
— caught during this session's audit.

Now: real TCP connect probes against the specific ports PLCs expose
(S7comm 102 for Siemens, EtherNet/IP CIP 44818 for Allen-Bradley/
Rockwell, Modbus TCP 502 for many other vendors), reporting real
open/closed status per port. This deliberately does NOT attempt to read
or write PLC memory/program state even when a port is open — doing so
against a live PLC controlling physical equipment is inherently
higher-risk than a passive port probe, and requires the vendor's own
protocol semantics (S7 "PDU negotiation" for Siemens, CIP "Forward Open"
for Rockwell) plus an explicit, deliberate opt-in — not something this
tool does implicitly during a routine assessment.
"""
from __future__ import annotations

import socket
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_PLC_PORTS: list[tuple[str, int, str]] = [
    ("S7comm (Siemens S7-300/400/1200/1500)", 102, "python-snap7 for PDU negotiation/CPU identification"),
    ("EtherNet/IP CIP (Allen-Bradley/Rockwell)", 44818, "pycomm3 for a real Forward Open / Identity request"),
    ("Modbus TCP (generic PLC)", 502, "ot_ics.modbus_analysis for a real register read"),
]


def _probe_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run(target: str, timeout: float = 3.0, **kwargs: Any) -> dict:
    """Real PLC-protocol port survey; deliberately does not read/write PLC state."""
    host = target.strip()
    if not host:
        return tool_result("ot_ics.plc_testing", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    open_count = 0
    port_results: dict[str, dict] = {}

    for name, port, next_step in _PLC_PORTS:
        is_open = _probe_port(host, port, timeout)
        port_results[name] = {"port": port, "open": is_open}
        if not is_open:
            continue
        open_count += 1
        findings.append(Finding(
            title=f"PLC-shaped service open on {host}:{port} ({name})",
            severity="high", confidence="certain",
            affected_asset=f"{host}:{port}",
            evidence=f"Real TCP connection established to {host}:{port}, the standard port "
                     f"for {name}. This tool does not read/write PLC state; use {next_step}.",
            remediation="PLCs frequently expose engineering/programming protocols with no "
                        "authentication — verify this PLC is not reachable outside an isolated "
                        "OT network segment, and that write access requires a physical key-switch "
                        "or explicit RUN/PROGRAM mode change, not just network access.",
            tool="ot_ics.plc_testing",
            references=["IEC-62443-3-3", "NIST-SP-800-82", "CWE-284"],
        ))

    if not findings:
        return tool_result(
            "ot_ics.plc_testing", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No PLC-shaped ports open on {host} among {len(_PLC_PORTS)} checked",
            metadata={"port_results": port_results},
        )

    return tool_result(
        "ot_ics.plc_testing", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"{open_count}/{len(_PLC_PORTS)} PLC-shaped port(s) open on {host}",
        metadata={"port_results": port_results, "note": "Port reachability only — no PLC memory/program read or write was attempted."},
    )


tool_registry.register("ot_ics.plc_testing", run, metadata={
    "name": "ot_ics.plc_testing",
    "domain": "ot_ics",
    "status": "completed",
    "description": "Real PLC-protocol port survey (S7comm/EtherNet-IP-CIP/Modbus); deliberately never reads/writes PLC memory or program state",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "Per-port connect timeout in seconds (default: 3.0)",
    },
})
