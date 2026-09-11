#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory.lateral_movement
Domain: active_directory
Real, read-only lateral-movement attack-surface enumeration: checks which
lateral-movement-relevant services (SMB, WinRM HTTP/HTTPS, RDP, RPC
endpoint mapper) are actually reachable on the target via real TCP
connects. Does not attempt any authentication or movement itself — this is
passive surface enumeration, matching the honesty standard already
established by kerberoast.py/domain_enum.py in this same directory.

Previously a generic "DNS resolve + bare HTTP GET" stub. Caught during this
session's audit.
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

_CONNECT_TIMEOUT = 3

# port -> (service label, MITRE technique most associated with lateral
# movement over that service)
_LATERAL_MOVEMENT_PORTS: dict[int, tuple[str, str]] = {
    445: ("SMB", "T1021.002"),
    5985: ("WinRM (HTTP)", "T1021.006"),
    5986: ("WinRM (HTTPS)", "T1021.006"),
    3389: ("RDP", "T1021.001"),
    135: ("RPC Endpoint Mapper", "T1021.003"),
}


def _probe_port(target: str, port: int, timeout: int = _CONNECT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


def run(target: str, **kwargs: Any) -> dict:
    """Enumerate reachable lateral-movement-relevant services via real TCP connects."""
    tool_name = "active_directory.lateral_movement"

    try:
        socket.gethostbyname(target)
    except socket.gaierror as e:
        return tool_result(tool_name, target, status=STATUS_FAILED, error=f"DNS resolution failed for {target}: {e}")

    reachable: list[dict] = []
    try:
        for port, (label, technique) in _LATERAL_MOVEMENT_PORTS.items():
            if _probe_port(target, port):
                reachable.append({"port": port, "service": label, "technique": technique})
    except Exception as e:  # noqa: BLE001 - unexpected socket-layer failures
        return tool_result(tool_name, target, status=STATUS_FAILED, error=f"Port probing failed: {e}")

    if not reachable:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"None of {len(_LATERAL_MOVEMENT_PORTS)} common lateral-movement service ports "
                    f"were reachable on {target}",
        )

    findings = [
        Finding(
            title=f"Lateral-Movement Surface: {svc['service']} Reachable",
            severity="medium",
            confidence="certain",
            affected_asset=f"{target}:{svc['port']}",
            evidence=f"Real TCP connect to {target}:{svc['port']} succeeded — {svc['service']} is reachable "
                     f"and is a common lateral-movement vector once valid credentials/tickets are obtained.",
            remediation="Restrict this service to authorized management subnets; enforce network "
                        "segmentation and require MFA for any credentialed access over this protocol.",
            tool=tool_name,
            references=["MITRE ATT&CK " + svc["technique"]],
        )
        for svc in reachable
    ]
    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real TCP probing found {len(reachable)} reachable lateral-movement-relevant "
                f"service(s) on {target}",
        metadata={"reachable_services": reachable},
    )


tool_registry.register("active_directory.lateral_movement", run, metadata={
    "name": "active_directory.lateral_movement",
    "domain": "active_directory",
    "status": "completed",
    "description": "Real, read-only enumeration of reachable lateral-movement-relevant services "
                    "(SMB/WinRM/RDP/RPC) via TCP connect probing",
    "parameters": {"target": "Target hostname or IP"},
})
