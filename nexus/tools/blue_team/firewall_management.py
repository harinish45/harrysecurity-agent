#!/usr/bin/env python3
"""
NEXUS-STRIKE — blue_team tool: Firewall Management
Domain: blue_team

Reviewing firewall configuration means reading the actual rule set — an
`iptables-save` export or a Windows Firewall `netsh advfirewall` export —
it cannot be inferred by probing a target over the network (a closed port
looks identical whether it's blocked by a good rule or simply unlisted).
This previously did a DNS resolve on `target` and checked a handful of
HTTP security response headers, calling that "firewall management" —
unrelated to any firewall rule — caught during this session's audit.

Now: if `target` is a real local file, this statically analyzes it as
either an `iptables-save` export or a Windows Firewall `netsh advfirewall
firewall show rule name=all` export (auto-detected), and flags genuine
misconfigurations: a default-ACCEPT chain policy, an unrestricted
`-j ACCEPT` rule with no source/port restriction, a `0.0.0.0/0`-source
ACCEPT rule with no destination port, and — for the Windows format — an
inbound Allow rule with RemoteIP/LocalPort both set to "Any". If `target`
isn't a readable file, it honestly reports STATUS_OUT_OF_SCOPE instead of
fabricating a target assessment from an unrelated HTTP header check.
"""
import os
import re

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_OUT_OF_SCOPE, tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_BYTES = 5 * 1024 * 1024


# Default-policy lines appear as either `:INPUT ACCEPT [0:0]` (real
# `iptables-save` output) or `-P INPUT ACCEPT` (`iptables -S`/`iptables -L`
# output) — both are matched so either export format is recognized.
_IPT_DEFAULT_POLICY_RE = re.compile(r'^(?::|-P\s+)(INPUT|OUTPUT|FORWARD)\s+ACCEPT\b', re.MULTILINE)
_IPT_RULE_RE = re.compile(r'^-A\s+(\S+)\s+(.*)$', re.MULTILINE)


def _analyze_iptables(text: str) -> list:
    findings = []

    default_accept = _IPT_DEFAULT_POLICY_RE.findall(text)
    if default_accept:
        findings.append(Finding(
            title=f"Default-ACCEPT chain polic{'y' if len(default_accept) == 1 else 'ies'}: "
                  f"{', '.join(sorted(set(default_accept)))}",
            severity="high",
            confidence="high",
            evidence="; ".join(f"-P {c} ACCEPT" for c in sorted(set(default_accept))),
            remediation="Set the default policy to DROP and explicitly ACCEPT only the "
                        "traffic that's required.",
        ))

    for chain, rest in _IPT_RULE_RE.findall(text):
        if "-j ACCEPT" not in rest and "-j DROP" not in rest and "-j REJECT" not in rest:
            continue
        if "-j ACCEPT" not in rest:
            continue
        has_source_restriction = bool(re.search(r'-s\s+(?!0\.0\.0\.0/0\b)\S+', rest))
        has_port_restriction = "--dport" in rest or "--sport" in rest
        no_source_flag = "-s " not in rest
        broad_source = bool(re.search(r'-s\s+0\.0\.0\.0/0\b', rest))

        if (no_source_flag or broad_source) and not has_port_restriction:
            findings.append(Finding(
                title=f"Unrestricted ACCEPT rule in {chain} chain",
                severity="critical",
                confidence="high",
                evidence=f"-A {chain} {rest}".strip(),
                remediation="Restrict this rule to a specific source and destination port "
                            "rather than accepting all traffic on the chain.",
            ))
        elif not has_source_restriction and has_port_restriction:
            findings.append(Finding(
                title=f"Any-source ACCEPT rule in {chain} chain",
                severity="medium",
                confidence="medium",
                evidence=f"-A {chain} {rest}".strip(),
                remediation="Consider restricting the source address range for this rule if "
                            "the service doesn't need to be reachable from anywhere.",
            ))

    return findings


# netsh separates each *rule* from the next with a blank line; within a
# single rule, the "Rule Name:" header is followed by its own dashes
# separator line and then that same rule's fields — so blocks are split on
# blank lines, not on the dashes (which simply don't match the field regex
# below and are harmlessly ignored).
_NETSH_BLOCK_SPLIT_RE = re.compile(r'\n\s*\n')
_NETSH_FIELD_RE = re.compile(r'^(\w[\w /]*?):\s*(.*)$', re.MULTILINE)


def _analyze_netsh(text: str) -> list:
    findings = []
    for block in _NETSH_BLOCK_SPLIT_RE.split(text):
        fields = {k.strip().lower(): v.strip() for k, v in _NETSH_FIELD_RE.findall(block)}
        if not fields:
            continue
        action = fields.get("action", "").lower()
        direction = fields.get("direction", "").lower()
        enabled = fields.get("enabled", "").lower()
        remote_ip = fields.get("remoteip", "").lower()
        local_port = fields.get("localport", "").lower()
        rule_name = fields.get("rule name", "unnamed rule")

        if action == "allow" and direction == "in" and enabled == "yes" \
                and remote_ip == "any" and local_port == "any":
            findings.append(Finding(
                title=f"Inbound Allow-Any rule: {rule_name}",
                severity="high",
                confidence="high",
                evidence=f"Rule Name: {rule_name}; Direction: In; Action: Allow; "
                         f"RemoteIP: Any; LocalPort: Any",
                remediation="Scope this rule to specific remote addresses and/or ports rather "
                            "than allowing any inbound source on any local port.",
            ))
    return findings


def _looks_like_iptables(text: str) -> bool:
    return bool(re.search(r'^-A\s+\S+', text, re.MULTILINE) or re.search(r'^-P\s+\S+', text, re.MULTILINE))


def _looks_like_netsh(text: str) -> bool:
    return "Rule Name:" in text or "RemoteIP:" in text


def run(target: str, **kwargs) -> dict:
    """blue_team tool: Firewall Management"""
    if not os.path.isfile(target):
        return tool_result(
            "blue_team.firewall_management", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"Firewall review of {target} requires the actual rule set — an "
                    f"`iptables-save` export or a Windows Firewall `netsh advfirewall` export — "
                    f"reachability over the network can't distinguish a good rule from an "
                    f"unlisted port",
            error="requires_case_data: target is not a readable local firewall-config file path",
            metadata={"requires": [
                "an `iptables-save` export, or",
                "a `netsh advfirewall firewall show rule name=all` export",
            ]},
        )

    try:
        if os.path.getsize(target) > _MAX_BYTES:
            return tool_result(
                "blue_team.firewall_management", target, status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} exceeds this tool's {_MAX_BYTES}-byte review cap",
                error="requires_case_data: file too large for inline review",
            )
        with open(target, "r", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return tool_result(
            "blue_team.firewall_management", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    fmt = None
    findings = []
    if _looks_like_iptables(text):
        fmt = "iptables"
        findings = _analyze_iptables(text)
    elif _looks_like_netsh(text):
        fmt = "netsh_advfirewall"
        findings = _analyze_netsh(text)
    else:
        return tool_result(
            "blue_team.firewall_management", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"{target} doesn't match a recognized firewall-export format "
                    f"(iptables-save or netsh advfirewall)",
            error="requires_case_data: unrecognized firewall config format",
        )

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "blue_team.firewall_management", target, status=status, findings=findings,
        summary=f"Analyzed {target} as {fmt} format; {len(findings)} misconfiguration(s) found",
        metadata={"format_detected": fmt},
    )


# Register with tool registry
tool_registry.register("blue_team.firewall_management", run, metadata={
    "name": "blue_team.firewall_management",
    "domain": "blue_team",
    "status": "completed",
    "description": "blue_team tool: statically analyzes a local iptables-save or netsh "
                    "advfirewall export for default-ACCEPT policies and unrestricted allow "
                    "rules; requires `target` to be a local config file path, not a network target",
    "parameters": {
        "target": "Local path to an iptables-save or netsh advfirewall export (not a domain/IP/URL)",
    },
})
