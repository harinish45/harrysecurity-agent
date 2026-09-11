#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: Risk Assessments
Domain: compliance

A real, severity-weighted risk summary over whatever upstream findings are
passed in (same correlation pattern as nexus/agents/analysis/
vuln_analyst_agent.py), plus its own direct signal: a raw attack-surface
probe (open common-port count). Previously identical to all 8 other
compliance.* tools (no aggregation, no direct signal) — caught during
this session's audit.
"""
import concurrent.futures
import socket

from nexus.tools.registry import tool_registry

_SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
_COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]


def run(target: str, **kwargs) -> dict:
    """compliance tool: Risk Assessments"""
    findings = []
    upstream_findings = kwargs.get("findings") or []

    if upstream_findings:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in upstream_findings:
            sev = str(f.get("severity", "info")).lower() if isinstance(f, dict) else "info"
            counts[sev] = counts.get(sev, 0) + 1
        total_weight = sum(_SEVERITY_WEIGHT.get(sev, 0) * count for sev, count in counts.items())
        max_weight = len(upstream_findings) * _SEVERITY_WEIGHT["critical"]
        risk_score = round((total_weight / max_weight) * 10, 1) if max_weight else 0.0
        findings.append(
            f"Aggregate risk score from {len(upstream_findings)} upstream finding(s): {risk_score}/10 "
            f"({counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
            f"{counts['low']} low, {counts['info']} info)"
        )
    else:
        findings.append("No upstream findings supplied to correlate — risk score based on direct signal only")

    def probe(port: int):
        try:
            with socket.create_connection((target, port), timeout=2):
                return port
        except OSError:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_COMMON_PORTS)) as executor:
        open_ports = sorted(p for p in executor.map(probe, _COMMON_PORTS) if p is not None)

    if open_ports:
        exposure = "high" if len(open_ports) >= 5 else ("medium" if len(open_ports) >= 2 else "low")
        findings.append(f"Direct attack-surface signal: {len(open_ports)} common port(s) open ({open_ports}) — {exposure} raw exposure")
    else:
        findings.append("Direct attack-surface signal: no common ports reachable — low raw exposure")

    return {"tool": "compliance.risk_assessments", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.risk_assessments", run, metadata={
    "name": "compliance.risk_assessments",
    "domain": "compliance",
    "status": "completed",
    "description": "Severity-weighted risk aggregation over upstream findings, plus a direct open-port attack-surface probe",
    "parameters": {
        "target": "Target domain, IP, or URL",
        "findings": "Optional list of upstream findings to correlate into a risk score",
    },
})
