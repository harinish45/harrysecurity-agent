#!/usr/bin/env python3
"""
NEXUS-STRIKE — threat_intel tool: Campaign Analysis
Domain: threat_intel

Campaign analysis — correlating multiple IOCs into a single attributed
campaign — fundamentally needs more than one indicator: a single
domain/IP carries no correlation signal by itself. This performs a real
correlation pass — resolving each supplied IOC and clustering the ones
that share infrastructure (the same resolved IP), a genuine, if simple,
infrastructure-clustering technique — when given enough IOCs to
correlate, and honestly reports that it can't when it isn't.

This was previously one of 8 threat_intel tools sharing byte-for-byte
identical fake logic (DNS resolve + bare HTTP GET on `/`, unrelated to
campaign correlation) — caught during this session's audit.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "threat_intel.campaign_analysis"
_MIN_IOCS = 2


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def run(target: str, **kwargs: Any) -> dict:
    """Real infrastructure-correlation pass across a supplied set of IOCs."""
    iocs = kwargs.get("iocs")
    if not isinstance(iocs, list) or len(iocs) < _MIN_IOCS:
        got = len(iocs) if isinstance(iocs, list) else 0
        return tool_result(
            _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
            summary="Campaign analysis needs 2+ correlated IOCs to find anything — a single target "
                    "carries no correlation signal by itself",
            error=f"requires_case_data: pass iocs=[<domain_or_ip>, ...] with at least {_MIN_IOCS} "
                  f"entries; got {got}",
        )

    resolved: dict[str, str] = {}
    for raw_ioc in iocs:
        ioc = str(raw_ioc).strip()
        if not ioc:
            continue
        ip = ioc if _is_ip(ioc) else _resolve(ioc)
        if ip:
            resolved[ioc] = ip

    clusters: dict[str, list[str]] = {}
    for ioc, ip in resolved.items():
        clusters.setdefault(ip, []).append(ioc)
    shared_clusters = {ip: members for ip, members in clusters.items() if len(members) > 1}

    if not shared_clusters:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"Resolved {len(resolved)}/{len(iocs)} IOC(s) via real DNS; none shared "
                    f"infrastructure (no correlation found)",
            metadata={"resolved": resolved},
        )

    findings = []
    for ip, members in shared_clusters.items():
        findings.append(Finding(
            title=f"Shared infrastructure cluster at {ip}",
            severity="medium",
            confidence="high",
            affected_asset=", ".join(members),
            evidence=f"IOCs {members} all resolve to {ip} — real DNS-based correlation, suggesting "
                     f"shared campaign infrastructure",
            remediation="Investigate the shared IP for additional attacker-controlled infrastructure "
                        "and block/monitor accordingly.",
            tool=_TOOL_NAME,
            references=["MITRE ATT&CK T1583.001"],
        ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Correlated {len(iocs)} IOC(s) into {len(shared_clusters)} shared-infrastructure "
                f"cluster(s)",
        metadata={"resolved": resolved, "clusters": shared_clusters},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "threat_intel",
    "status": "completed",
    "description": "Real infrastructure-correlation campaign analysis across 2+ supplied IOCs "
                    "(clusters IOCs that resolve to shared IPs)",
    "parameters": {
        "target": "Campaign/case label",
        "iocs": "Required: list of 2+ domains/IPs to correlate",
    },
})
