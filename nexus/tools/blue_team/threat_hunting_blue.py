#!/usr/bin/env python3
"""
NEXUS-STRIKE — blue_team tool: Threat Hunting Blue
Domain: blue_team

Blue-team threat hunting cross-references indicators already present in
telemetry against known-bad patterns — it needs that telemetry, not a
network probe. This previously did a DNS resolve on `target` and checked
for a handful of security response headers over HTTP, always reporting
status "completed" — unrelated to hunting anything — caught during this
session's audit.

Now: if `target` is a real local file, this regex-extracts domain/IPv4/URL
IOCs and cross-references them against three concrete, network-agnostic
heuristics: (1) domains under TLDs disproportionately abused for
throwaway/malicious infrastructure because of their low registration cost
(.xyz/.top/.club/.work/.click/.link/.icu/.zip), (2) RFC1918 private IPv4
addresses appearing in what should be external-facing log data (a real
leak of internal addressing, or a misconfigured proxy), and (3) URLs that
address a server by raw IP literal instead of a hostname — a common
evasion tactic to dodge domain-reputation blocklists. If `target` isn't a
readable file, it honestly reports STATUS_OUT_OF_SCOPE instead of
fabricating a target assessment from an unrelated HTTP header check.
"""
import ipaddress
import os
import re

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_OUT_OF_SCOPE, tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_BYTES = 10 * 1024 * 1024

_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?!\d+\b)[a-zA-Z]{2,24}\b'
)
_URL_RE = re.compile(r'\bhttps?://([^/\s"\'<>]+)', re.IGNORECASE)

_ABUSED_TLDS = {"xyz", "top", "club", "work", "click", "link", "icu", "zip"}


def run(target: str, **kwargs) -> dict:
    """blue_team tool: Threat Hunting Blue"""
    if not os.path.isfile(target):
        return tool_result(
            "blue_team.threat_hunting_blue", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"Threat hunting over {target} requires real telemetry containing IOCs to "
                    f"cross-reference — a bare domain/IP/URL is not a body of telemetry",
            error="requires_case_data: target is not a readable local file path",
            metadata={"requires": ["a local telemetry/log file path as `target`"]},
        )

    try:
        if os.path.getsize(target) > _MAX_BYTES:
            return tool_result(
                "blue_team.threat_hunting_blue", target, status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} exceeds this tool's {_MAX_BYTES}-byte hunt cap",
                error="requires_case_data: file too large for inline hunting",
            )
        with open(target, "r", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return tool_result(
            "blue_team.threat_hunting_blue", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    domains = sorted(set(_DOMAIN_RE.findall(text)))
    ips = sorted(set(_IPV4_RE.findall(text)))
    url_hosts = sorted(set(_URL_RE.findall(text)))

    findings = []

    abused_tld_hits = [d for d in domains if d.rsplit(".", 1)[-1].lower() in _ABUSED_TLDS]
    if abused_tld_hits:
        findings.append(Finding(
            title=f"{len(abused_tld_hits)} domain(s) under commonly-abused low-cost TLDs",
            severity="low",
            confidence="low",
            affected_asset=target,
            evidence=", ".join(abused_tld_hits[:10]),
            remediation="Low intrinsic confidence — cross-check against threat-intel feeds "
                        "before acting; many legitimate sites also use these TLDs.",
        ))

    private_ip_hits = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_private:
                private_ip_hits.append(ip)
        except ValueError:
            continue
    if private_ip_hits:
        findings.append(Finding(
            title=f"{len(private_ip_hits)} RFC1918 private IPv4 address(es) found in telemetry",
            severity="low",
            confidence="medium",
            affected_asset=target,
            evidence=", ".join(private_ip_hits[:10]),
            remediation="If this telemetry is meant to be external-facing, private addresses "
                        "here indicate either an internal-address leak or NAT/proxy "
                        "misconfiguration worth reviewing.",
        ))

    ip_literal_urls = [h for h in url_hosts if _IPV4_RE.fullmatch(h.split(":")[0])]
    if ip_literal_urls:
        findings.append(Finding(
            title=f"{len(ip_literal_urls)} URL(s) address a host by raw IP literal",
            severity="medium",
            confidence="medium",
            affected_asset=target,
            evidence=", ".join(ip_literal_urls[:10]),
            remediation="IP-literal URLs are a common technique to evade domain-reputation "
                        "blocklists — investigate the destination and purpose of these requests.",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "blue_team.threat_hunting_blue", target, status=status, findings=findings,
        summary=f"Cross-referenced {len(domains)} domain(s), {len(ips)} IPv4 address(es), and "
                f"{len(url_hosts)} URL host(s) from {target}; {len(findings)} finding(s)",
        metadata={
            "domains_seen": len(domains), "ips_seen": len(ips), "url_hosts_seen": len(url_hosts),
            "abused_tld_hits": abused_tld_hits, "private_ip_hits": private_ip_hits,
            "ip_literal_urls": ip_literal_urls,
        },
    )


# Register with tool registry
tool_registry.register("blue_team.threat_hunting_blue", run, metadata={
    "name": "blue_team.threat_hunting_blue",
    "domain": "blue_team",
    "status": "completed",
    "description": "blue_team tool: cross-references IOCs extracted from a local telemetry "
                    "file against abused-TLD, private-IP-leak, and IP-literal-URL heuristics; "
                    "requires `target` to be a local file path, not a network target",
    "parameters": {
        "target": "Local path to a telemetry/log file to hunt through (not a domain/IP/URL)",
    },
})
