#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.autorecon
Domain: network

Previously a plain generic port sweep (byte-for-byte identical to
nfs_enum.py, snmp_enum.py, etc. before this fix) — despite the name it
never chained anything. Caught during this session's audit.

Now: a real composite that chains network.port_scan -> network.service_enum
-> network.banner_grab, the same "cast a wide net, then go deep only on
what's actually open" pattern `autorecon`/`nmap -sV --script banner`
follow. port_scan's discovered open ports are fed into service_enum and
banner_grab's `ports=` argument so they only re-probe ports already known
to be open, instead of re-sweeping the entire port list three times.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs: Any) -> dict:
    """Real composite recon chain: port_scan -> service_enum -> banner_grab."""
    host = target.strip()
    if not host:
        return tool_result("network.autorecon", target, status=STATUS_FAILED, error="Empty target")

    try:
        port_scan = tool_registry.get("network.port_scan")
        service_enum = tool_registry.get("network.service_enum")
        banner_grab = tool_registry.get("network.banner_grab")
    except KeyError as e:
        return tool_result("network.autorecon", target, status=STATUS_FAILED, error=f"Required sub-tool missing: {e}")

    scan_result = port_scan(target=host)
    open_ports = [
        int(f["affected_asset"].rsplit(":", 1)[-1])
        for f in scan_result.get("findings", [])
        if ":" in f.get("affected_asset", "")
    ]

    if not open_ports:
        return tool_result(
            "network.autorecon", target,
            status=STATUS_NO_FINDINGS,
            summary=f"port_scan found no open ports on {host}; nothing to enumerate further",
            metadata={"port_scan": scan_result.get("metadata", {})},
        )

    service_result = service_enum(target=host, ports=open_ports)
    banner_result = banner_grab(target=host, ports=open_ports)

    findings: list[Finding] = []
    for stage_name, stage_result in (
        ("port_scan", scan_result),
        ("service_enum", service_result),
        ("banner_grab", banner_result),
    ):
        for f in stage_result.get("findings", []):
            f = dict(f)
            f["id"] = ""  # re-assign to avoid id collisions across stages
            f.setdefault("evidence", "")
            f["evidence"] = f"[{stage_name}] " + f["evidence"]
            findings.append(Finding(**f))

    return tool_result(
        "network.autorecon", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"autorecon chain on {host}: {len(open_ports)} open port(s) -> "
                f"{len(service_result.get('findings', []))} service finding(s) -> "
                f"{len(banner_result.get('findings', []))} banner finding(s)",
        metadata={
            "open_ports": open_ports,
            "port_scan_metadata": scan_result.get("metadata", {}),
            "service_enum_metadata": service_result.get("metadata", {}),
            "banner_grab_metadata": banner_result.get("metadata", {}),
        },
    )


# Register with tool registry
tool_registry.register("network.autorecon", run, metadata={
    "name": "network.autorecon",
    "domain": "network",
    "status": "completed",
    "description": "Real composite recon chain: port_scan -> service_enum -> banner_grab, scoped to discovered open ports",
    "parameters": {
        "target": "Target IP or hostname",
    },
})
