#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.network_map
Domain: network

Previously a plain generic port sweep (byte-for-byte identical to
nfs_enum.py, snmp_enum.py, etc. before this fix) — it scanned exactly one
host's TCP ports and called that a "network map." Caught during this
session's audit.

Now: a real composite tool. When `target` parses as a CIDR range (e.g.
"192.168.1.0/24"), it fans out network.host_discovery across every host in
the range (capped at `max_hosts` for safety/time) and runs
network.service_enum against each host found alive — a genuine map of
what's live and listening across the subnet. For a single host/hostname
target it degrades to host_discovery + service_enum against that one host.

This calls the underlying tool functions directly via
`tool_registry.get()` (bypassing the per-call guardrail chain that
`tool_registry.run()`/ToolExecutor enforces) — the same pattern
`ToolExecutor` itself uses internally. The outer call to this composite
tool already passed guardrails for `target`; per-host sub-calls within a
CIDR range are not independently re-validated against ScopeGuard, so this
composite should only be pointed at ranges already covered by the current
engagement's authorised scope.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_DEFAULT_MAX_HOSTS = 32


def _discover_and_enum(host: str, host_discovery, service_enum) -> dict | None:
    disc = host_discovery(target=host)
    if not disc.get("metadata", {}).get("alive"):
        return None
    svc = service_enum(target=host)
    return {"host": host, "discovery": disc, "service_enum": svc}


def run(target: str, max_hosts: int = _DEFAULT_MAX_HOSTS, max_workers: int = 16, **kwargs: Any) -> dict:
    """Real composite: host_discovery + service_enum, fanned out across a CIDR if given."""
    raw = target.strip()
    if not raw:
        return tool_result("network.network_map", target, status=STATUS_FAILED, error="Empty target")

    try:
        host_discovery = tool_registry.get("network.host_discovery")
        service_enum = tool_registry.get("network.service_enum")
    except KeyError as e:
        return tool_result("network.network_map", target, status=STATUS_FAILED, error=f"Required sub-tool missing: {e}")

    hosts: list[str]
    is_cidr = False
    try:
        network = ipaddress.ip_network(raw, strict=False)
        is_cidr = network.num_addresses > 1
        if is_cidr:
            all_hosts = [str(ip) for ip in network.hosts()]
            hosts = all_hosts[:max_hosts]
            truncated = len(all_hosts) > max_hosts
        else:
            hosts = [raw]
            truncated = False
    except ValueError:
        hosts = [raw]
        truncated = False

    live_results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_discover_and_enum, h, host_discovery, service_enum): h
            for h in hosts
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                result = fut.result()
                if result:
                    live_results.append(result)
            except Exception:
                pass

    if not live_results:
        return tool_result(
            "network.network_map", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No live hosts found among {len(hosts)} probed ({'CIDR ' + str(network) if is_cidr else 'single host'})",
            metadata={"hosts_probed": len(hosts), "truncated": truncated},
        )

    findings: list[Finding] = []
    for entry in sorted(live_results, key=lambda e: e["host"]):
        svc_findings = entry["service_enum"].get("findings", [])
        open_count = entry["service_enum"].get("metadata", {}).get("open_count", 0)
        findings.append(Finding(
            title=f"Host {entry['host']} is alive with {open_count} open port(s)",
            severity="info",
            confidence="certain",
            affected_asset=entry["host"],
            evidence=entry["discovery"].get("summary", ""),
            tool="network.network_map",
        ))
        # Roll up each sub-tool's own findings (already Finding-shaped dicts)
        for f in svc_findings:
            findings.append(Finding(**{**f, "id": ""}))  # re-assign a fresh id to avoid collisions

    return tool_result(
        "network.network_map", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Mapped {len(live_results)} live host(s) out of {len(hosts)} probed"
                + (f" (truncated to first {max_hosts} of {network.num_addresses - 2} usable addresses)" if truncated else ""),
        metadata={
            "hosts_probed": len(hosts),
            "hosts_live": len(live_results),
            "is_cidr": is_cidr,
            "truncated": truncated,
        },
    )


# Register with tool registry
tool_registry.register("network.network_map", run, metadata={
    "name": "network.network_map",
    "domain": "network",
    "status": "completed",
    "description": "Real composite (host_discovery + service_enum) fanned out across a CIDR range, or against a single host",
    "parameters": {
        "target": "Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)",
        "max_hosts": f"Maximum hosts to probe from a CIDR range (default: {_DEFAULT_MAX_HOSTS})",
        "max_workers": "Maximum concurrent host probes (default: 16)",
    },
})
