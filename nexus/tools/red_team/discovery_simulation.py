#!/usr/bin/env python3
"""
NEXUS-STRIKE — red_team.discovery_simulation
Domain: red_team
Real, active simulation of MITRE ATT&CK Discovery (TA0007). Unlike the other
red_team.*_simulation tools, Discovery techniques (host liveness checks,
service/port scanning, basic system-info gathering) are inherently safe to
perform for real — there is no meaningfully "simulated" version of a network
scan — so this tool genuinely runs discovery against the target by reusing
the existing, real network tools already in this codebase
(network.host_discovery, network.port_scan) rather than re-implementing or
faking that logic, and reports the results framed by the ATT&CK technique
each one maps to.
"""
from __future__ import annotations

import socket
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.red_team._ttp_common import resolve_target

# A small, fast port set for discovery-simulation framing — the full
# service_enum/port_scan port list is available via network.port_scan
# directly for operators who want a deeper sweep; this tool's job is TTP
# framing of discovery, not being the primary port-scanning tool.
_DISCOVERY_PORTS = [21, 22, 23, 25, 53, 80, 111, 135, 139, 443, 445, 3306, 3389, 5432, 8080]


def run(
    target: str,
    ports: list[int] | None = None,
    **kwargs: Any,
) -> dict:
    """Run real, active MITRE ATT&CK Discovery (TA0007) techniques against a target.

    Parameters
    ----------
    target : str
        Target IP or hostname.
    ports : list[int], optional
        Ports to check for T1046 Network Service Discovery framing.
        Defaults to a small, fast, well-known port set.

    Notes
    -----
    Per-probe timing is left to network.host_discovery/network.port_scan's
    own defaults. A `timeout=` kwarg is deliberately NOT forwarded to
    `tool_registry.run()` here: `ToolExecutor.run()` reserves the keyword
    `timeout` for its OWN overall per-call deadline and does not pass it
    through to the wrapped tool's `timeout` parameter — forwarding one
    value into both silently truncates the sub-scan instead of tuning its
    per-probe timing.
    """
    findings: list[Finding] = []
    host = target.strip()
    if not host:
        return tool_result("red_team.discovery_simulation", target, status=STATUS_FAILED, error="Empty target")

    # ── T1082 — System Information Discovery: real DNS/PTR gathering ───────
    ip, dns_note = resolve_target(host)
    metadata: dict[str, Any] = {"dns_resolved_ip": ip}
    if ip:
        ptr_note = ""
        try:
            ptr_host = socket.gethostbyaddr(ip)[0]
            ptr_note = f" Reverse DNS: {ip} -> {ptr_host}."
        except (socket.herror, socket.gaierror):
            pass
        findings.append(Finding(
            title="[EXECUTED] Discovery: System Information Discovery (T1082)",
            severity="info",
            confidence="certain",
            affected_asset=host,
            evidence=f"{dns_note}.{ptr_note}",
            remediation=(
                "Confirm DNS query logging/anomaly detection is active for internal "
                "resolvers if this discovery originated from inside the network."
            ),
            tool="red_team.discovery_simulation",
            references=["https://attack.mitre.org/techniques/T1082/"],
        ))
    else:
        findings.append(Finding(
            title="[EXECUTED] Discovery: System Information Discovery (T1082) — resolution failed",
            severity="info",
            confidence="high",
            affected_asset=host,
            evidence=dns_note,
            remediation="Target does not resolve; discovery cannot proceed further for this asset.",
            tool="red_team.discovery_simulation",
            references=["https://attack.mitre.org/techniques/T1082/"],
        ))
        return tool_result(
            "red_team.discovery_simulation", target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary="Discovery simulation halted: target did not resolve.",
            metadata=metadata,
        )

    # ── T1018 — Remote System Discovery: real host-liveness check ──────────
    # Reuses the existing, real network.host_discovery tool rather than
    # re-implementing ICMP/TCP/ARP liveness probing.
    host_discovery_result = tool_registry.run("network.host_discovery", target=host)
    metadata["host_discovery"] = {
        "status": host_discovery_result.get("status"),
        "summary": host_discovery_result.get("summary"),
    }
    hd_findings = host_discovery_result.get("findings") or []
    if hd_findings:
        for f in hd_findings:
            findings.append(Finding(
                title=f"[EXECUTED] Discovery: Remote System Discovery (T1018) — {f.get('title', 'host liveness')}",
                severity="info",
                confidence=f.get("confidence", "high"),
                affected_asset=host,
                evidence=f.get("evidence", host_discovery_result.get("summary", "")),
                remediation=(
                    "Confirm internal network-scan detection (unusual ICMP/TCP sweep volume "
                    "from a single source) is alerting for this activity."
                ),
                tool="red_team.discovery_simulation",
                references=["https://attack.mitre.org/techniques/T1018/"],
            ))
    else:
        findings.append(Finding(
            title="[EXECUTED] Discovery: Remote System Discovery (T1018) — host not confirmed alive",
            severity="info",
            confidence="medium",
            affected_asset=host,
            evidence=host_discovery_result.get("summary", "No liveness confirmation from network.host_discovery."),
            remediation="No action needed if this is expected for the target.",
            tool="red_team.discovery_simulation",
            references=["https://attack.mitre.org/techniques/T1018/"],
        ))

    # ── T1046 — Network Service Discovery: real port scan ──────────────────
    # Reuses the existing, real network.port_scan tool rather than
    # re-implementing socket-level scanning.
    scan_ports = ports or _DISCOVERY_PORTS
    port_scan_result = tool_registry.run(
        "network.port_scan", target=host, ports=scan_ports,
    )
    metadata["port_scan"] = {
        "status": port_scan_result.get("status"),
        "summary": port_scan_result.get("summary"),
        "ports_checked": scan_ports,
    }
    ps_findings = port_scan_result.get("findings") or []
    if ps_findings:
        for f in ps_findings:
            findings.append(Finding(
                title=f"[EXECUTED] Discovery: Network Service Discovery (T1046) — {f.get('title', 'open service')}",
                severity="info",
                confidence=f.get("confidence", "high"),
                affected_asset=host,
                evidence=f.get("evidence", ""),
                remediation=(
                    "Confirm network IDS/NetFlow alerting fires on a sequential multi-port "
                    "connection sweep from a single source in this timeframe."
                ),
                tool="red_team.discovery_simulation",
                references=["https://attack.mitre.org/techniques/T1046/"],
            ))
    else:
        findings.append(Finding(
            title=f"[EXECUTED] Discovery: Network Service Discovery (T1046) — no open ports found ({len(scan_ports)} checked)",
            severity="info",
            confidence="high",
            affected_asset=host,
            evidence=port_scan_result.get("summary", f"No open ports among {scan_ports}."),
            remediation="No action needed; re-verify if the target's exposed services change.",
            tool="red_team.discovery_simulation",
            references=["https://attack.mitre.org/techniques/T1046/"],
        ))

    executed = sum(1 for f in findings if "[EXECUTED]" in f.title)

    return tool_result(
        "red_team.discovery_simulation", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=(
            f"Discovery simulation complete: {executed} real ATT&CK Discovery technique "
            f"observation(s) (T1082/T1018/T1046) executed against {host} via "
            f"network.host_discovery and network.port_scan."
        ),
        metadata=metadata,
    )


tool_registry.register("red_team.discovery_simulation", run, metadata={
    "name": "red_team.discovery_simulation",
    "domain": "red_team",
    "status": "completed",
    "description": (
        "Real, active MITRE ATT&CK Discovery (TA0007) simulation — genuinely performs "
        "host-liveness (T1018) and network-service (T1046) discovery against the target "
        "via network.host_discovery/network.port_scan, plus real DNS-based system-info "
        "discovery (T1082), framed by the ATT&CK technique each result maps to."
    ),
    "parameters": {
        "target": "Target IP or hostname",
        "ports": "Ports to check for T1046 framing (default: small well-known port set)",
    },
})
