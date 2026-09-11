#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.firewall_detect
Domain: network

Previously a plain generic port sweep (byte-for-byte identical to
nfs_enum.py, snmp_enum.py, etc. before this fix) — it reported which ports
answered but never actually attempted to detect a firewall. Caught during
this session's audit.

Now: a real differential TCP probe. Without raw sockets (no admin/root
assumed) we can still distinguish three real outcomes per port using a
plain `connect()`:
  - a fast SYN-ACK  -> port OPEN
  - an immediate connection refusal (RST) -> port CLOSED, no firewall
    filtering that port
  - silence until the connect timeout -> the SYN was dropped, which is
    the signature of a stateful firewall / packet filter (an unfiltered
    closed port replies with RST near-instantly; a filtered one doesn't
    reply at all)
This is the same open/closed/filtered classification `nmap -sT` reports,
implemented without raw sockets.
"""
from __future__ import annotations

import socket
import time
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry

_DEFAULT_PROBE_PORTS = [22, 80, 443, 3389, 8080]
# A port picked to almost always be closed-not-filtered on a real host —
# used as a baseline "what does an unfiltered RST look like here" sample.
_LIKELY_CLOSED_PORT = 1

_RST_FAST_THRESHOLD_S = 0.5  # a same-host TCP RST typically arrives well under this


def _classify_port(host: str, port: int, timeout: float) -> dict:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = time.monotonic() - start
            return {"port": port, "state": "open", "elapsed_s": round(elapsed, 3)}
    except ConnectionRefusedError:
        elapsed = time.monotonic() - start
        return {"port": port, "state": "closed", "elapsed_s": round(elapsed, 3), "detail": "RST received"}
    except socket.timeout:
        elapsed = time.monotonic() - start
        return {"port": port, "state": "filtered", "elapsed_s": round(elapsed, 3), "detail": "no response before timeout"}
    except OSError as e:
        elapsed = time.monotonic() - start
        return {"port": port, "state": "error", "elapsed_s": round(elapsed, 3), "detail": str(e)[:120]}


def run(target: str, ports: list[int] | None = None, timeout: float = 2.5, **kwargs: Any) -> dict:
    """Differential TCP probe (open/closed/filtered) to infer firewall presence."""
    host = target.strip()
    if not host:
        return tool_result("network.firewall_detect", target, status=STATUS_FAILED, error="Empty target")

    probe_ports = list(ports) if ports else list(_DEFAULT_PROBE_PORTS)
    if _LIKELY_CLOSED_PORT not in probe_ports:
        probe_ports = probe_ports + [_LIKELY_CLOSED_PORT]

    results = [_classify_port(host, p, timeout) for p in probe_ports]

    open_ports = [r for r in results if r["state"] == "open"]
    closed_ports = [r for r in results if r["state"] == "closed"]
    filtered_ports = [r for r in results if r["state"] == "filtered"]

    findings: list[Finding] = []

    for r in results:
        findings.append(Finding(
            title=f"Port {r['port']}/tcp on {host}: {r['state']}",
            severity="info",
            confidence="certain" if r["state"] in ("open", "closed", "filtered") else "medium",
            affected_asset=f"{host}:{r['port']}",
            evidence=f"state={r['state']}, elapsed={r['elapsed_s']}s, detail={r.get('detail', '')}",
            tool="network.firewall_detect",
        ))

    if filtered_ports and closed_ports:
        # Some ports RST fast, others are silently dropped -> classic
        # stateful/packet-filtering firewall signature (selective filtering,
        # not "host down").
        findings.append(Finding(
            title=f"Differential filtering detected on {host}: {len(filtered_ports)} filtered "
                  f"vs {len(closed_ports)} closed (RST) among {len(results)} probed ports",
            severity="medium",
            confidence="high",
            affected_asset=host,
            evidence=f"filtered={[r['port'] for r in filtered_ports]}, closed={[r['port'] for r in closed_ports]}",
            remediation="Confirm this differential filtering is intentional security policy, "
                        "not an unmonitored gap.",
            tool="network.firewall_detect",
        ))
    elif filtered_ports and not closed_ports and not open_ports:
        findings.append(Finding(
            title=f"All {len(filtered_ports)} probed ports on {host} silently dropped connections",
            severity="low",
            confidence="medium",
            affected_asset=host,
            evidence="Every probe timed out with no RST — consistent with a default-drop "
                     "firewall policy (or the host being unreachable/down).",
            tool="network.firewall_detect",
        ))
    elif not filtered_ports:
        findings.append(Finding(
            title=f"No differential filtering detected on {host}",
            severity="info",
            confidence="medium",
            affected_asset=host,
            evidence=f"All probed ports returned open or RST-closed (no silent drops among "
                     f"{len(results)} probes) — no evidence of a stateful firewall dropping SYNs.",
            tool="network.firewall_detect",
        ))

    return tool_result(
        "network.firewall_detect", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Probed {len(results)} ports on {host}: {len(open_ports)} open, "
                f"{len(closed_ports)} closed, {len(filtered_ports)} filtered",
        metadata={"probe_results": results},
    )


# Register with tool registry
tool_registry.register("network.firewall_detect", run, metadata={
    "name": "network.firewall_detect",
    "domain": "network",
    "status": "completed",
    "description": "Real differential TCP probe (RST vs timeout vs SYN-ACK) across ports to infer firewall/packet-filtering",
    "parameters": {
        "target": "Target IP or hostname",
        "ports": "Optional list of ports to probe (default: 22,80,443,3389,8080 plus a baseline port)",
        "timeout": "Per-port connect timeout in seconds (default: 2.5)",
    },
})
