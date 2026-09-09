#!/usr/bin/env python3
"""
NEXUS-STRIKE — ot_ics.industrial_protocol_reviews
Domain: ot_ics

Previously checked real port reachability but never spoke any ICS
protocol at all (byte-for-byte identical to plc_testing.py,
scada_security.py, modbus_analysis.py, dnp3_testing.py before this fix)
— caught during this session's audit.

Now: real TCP connect probes across the standard ports for each major ICS
protocol family (Modbus, S7comm, DNP3, EtherNet/IP CIP, IEC-60870-5-104),
reporting real open/closed status per protocol — and, when Modbus (502)
is found open, chains into ot_ics.modbus_analysis for a real protocol-
level query rather than just reporting the port. Full protocol-level
interaction with the other protocols requires a protocol-specific library
(python-snap7 for S7comm, pydnp3 for DNP3, cpppo/pycomm3 for EtherNet/IP
CIP) that isn't installed here — that limitation is reported honestly per
protocol rather than faked.
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

_PROTOCOLS: list[tuple[str, int, str]] = [
    ("Modbus TCP", 502, "pymodbus / hand-rolled framing (see ot_ics.modbus_analysis for a real query)"),
    ("S7comm (Siemens S7)", 102, "python-snap7"),
    ("DNP3", 20000, "pydnp3 (see ot_ics.dnp3_testing for a real link-layer frame)"),
    ("EtherNet/IP CIP", 44818, "pycomm3 / cpppo"),
    ("IEC-60870-5-104", 2404, "a dedicated IEC-104 library (e.g. c104/lib60870 bindings)"),
]


def _probe_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run(target: str, timeout: float = 3.0, **kwargs: Any) -> dict:
    """Real multi-protocol ICS port survey with an honest per-protocol capability note."""
    host = target.strip()
    if not host:
        return tool_result("ot_ics.industrial_protocol_reviews", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    open_protocols: list[str] = []
    port_results: dict[str, dict] = {}

    for name, port, required_lib in _PROTOCOLS:
        is_open = _probe_port(host, port, timeout)
        port_results[name] = {"port": port, "open": is_open}
        if not is_open:
            continue
        open_protocols.append(name)
        findings.append(Finding(
            title=f"{name} port {port} open on {host}",
            severity="high", confidence="certain",
            affected_asset=f"{host}:{port}",
            evidence=f"Real TCP connection established to {host}:{port} — this is the "
                     f"standard port for {name}. Full protocol-level interaction requires "
                     f"{required_lib}, which is not available in this run.",
            remediation=f"Restrict {name} to an isolated OT network segment; most ICS "
                        f"protocols (Modbus, DNP3 without secure-authentication extensions, "
                        f"S7comm on older CPUs) have weak or no native authentication.",
            tool="ot_ics.industrial_protocol_reviews",
            references=["IEC-62443-3-3", "NIST-SP-800-82"],
        ))

    if open_protocols and "Modbus TCP" in open_protocols:
        try:
            modbus_analysis = tool_registry.get("ot_ics.modbus_analysis")
            modbus_result = modbus_analysis(target=host, timeout=timeout)
            for f in modbus_result.get("findings", []):
                f = dict(f)
                f["id"] = ""
                f["title"] = "[chained modbus_analysis] " + f.get("title", "")
                findings.append(Finding(**f))
        except KeyError:
            pass

    if not findings:
        return tool_result(
            "ot_ics.industrial_protocol_reviews", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No open ports among {len(_PROTOCOLS)} surveyed ICS protocol ports on {host}",
            metadata={"port_results": port_results},
        )

    return tool_result(
        "ot_ics.industrial_protocol_reviews", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"{len(open_protocols)}/{len(_PROTOCOLS)} surveyed ICS protocol port(s) open on {host}: {open_protocols}",
        metadata={"port_results": port_results},
    )


tool_registry.register("ot_ics.industrial_protocol_reviews", run, metadata={
    "name": "ot_ics.industrial_protocol_reviews",
    "domain": "ot_ics",
    "status": "completed",
    "description": "Real multi-protocol ICS port survey (Modbus/S7comm/DNP3/EtherNet-IP/IEC-104) with chained real Modbus query when found; honest per-protocol library requirement otherwise",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "Per-port connect timeout in seconds (default: 3.0)",
    },
})
