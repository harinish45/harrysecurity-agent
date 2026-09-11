#!/usr/bin/env python3
"""
NEXUS-STRIKE — incident_response tool: Threat Hunting
Domain: incident_response

Threat hunting is a hypothesis-driven search through existing telemetry
(logs, memory artifacts, proxy history) for indicators an automated alert
missed — it needs that telemetry, not a network probe. This previously
hashed `target` as if it were a file on disk (it never was) and checked
for the literal substrings "malware"/"backdoor"/"trojan"/etc., always
reporting status "completed" — caught during this session's audit.

Now: if `target` is a real local file, this extracts domain/hash IOCs (the
same regex extraction as `incident_response.ioc_collection`) and then
hunts within them for two concrete signals a plain extraction wouldn't
surface: (1) domains whose first label has high Shannon entropy — the
classic DGA (domain-generation-algorithm) fingerprint, since a hand-picked
hostname reads very differently from a randomly-generated one — and (2) a
hash value that recurs many times across the artifact, which in a case
file usually means "this is the indicator the case is about", not noise.
If `target` isn't a readable file, it honestly reports STATUS_OUT_OF_SCOPE
instead of fabricating a hash of an unrelated string.
"""
import math
import os
import re
from collections import Counter

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_OUT_OF_SCOPE, tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_BYTES = 10 * 1024 * 1024

_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?!\d+\b)[a-zA-Z]{2,24}\b'
)

_ENTROPY_THRESHOLD = 3.5
_MIN_LABEL_LEN = 8
_REPEAT_THRESHOLD = 3


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def run(target: str, **kwargs) -> dict:
    """incident_response tool: Threat Hunting"""
    if not os.path.isfile(target):
        return tool_result(
            "incident_response.threat_hunting", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"Threat hunting over {target} requires real telemetry to hunt through — "
                    f"logs, memory-dump strings, or proxy history — a bare domain/IP/URL is "
                    f"not a body of telemetry to search",
            error="requires_case_data: target is not a readable local file path",
            metadata={"requires": ["a local telemetry/case-artifact file path as `target`"]},
        )

    try:
        if os.path.getsize(target) > _MAX_BYTES:
            return tool_result(
                "incident_response.threat_hunting", target, status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} exceeds this tool's {_MAX_BYTES}-byte hunt cap",
                error="requires_case_data: file too large for inline hunting",
            )
        with open(target, "r", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return tool_result(
            "incident_response.threat_hunting", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    domains = sorted(set(_DOMAIN_RE.findall(text)))
    sha256_all = _SHA256_RE.findall(text)
    remaining = _SHA256_RE.sub(" ", text)
    sha1_all = _SHA1_RE.findall(remaining)
    remaining = _SHA1_RE.sub(" ", remaining)
    md5_all = _MD5_RE.findall(remaining)
    hash_counts = Counter(sha256_all + sha1_all + md5_all)

    findings = []
    dga_hits = []
    for domain in domains:
        label = domain.split(".")[0]
        if len(label) >= _MIN_LABEL_LEN:
            entropy = _shannon_entropy(label.lower())
            if entropy >= _ENTROPY_THRESHOLD:
                dga_hits.append((domain, round(entropy, 2)))
    if dga_hits:
        findings.append(Finding(
            title=f"{len(dga_hits)} high-entropy domain(s) resembling DGA output",
            severity="medium",
            confidence="medium",
            affected_asset=target,
            evidence="; ".join(f"{d} (entropy={e})" for d, e in dga_hits[:10]),
            remediation="Check these domains against threat-intel/DNS-reputation feeds; "
                        "high label entropy is suggestive of algorithmically-generated "
                        "C2 infrastructure, not conclusive on its own.",
        ))

    recurring = {h: c for h, c in hash_counts.items() if c >= _REPEAT_THRESHOLD}
    if recurring:
        top = sorted(recurring.items(), key=lambda kv: -kv[1])[:5]
        findings.append(Finding(
            title=f"{len(recurring)} hash indicator(s) recur {_REPEAT_THRESHOLD}+ times in the artifact",
            severity="medium",
            confidence="medium",
            affected_asset=target,
            evidence="; ".join(f"{h} x{c}" for h, c in top),
            remediation="A hash recurring throughout a case artifact is usually the indicator "
                        "the case centers on — prioritize it for enrichment/blocking.",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "incident_response.threat_hunting", target, status=status, findings=findings,
        summary=f"Hunted {len(domains)} domain(s) and {len(hash_counts)} unique hash(es) in "
                f"{target}; {len(findings)} hunting signal(s) found",
        metadata={
            "domains_seen": len(domains),
            "unique_hashes_seen": len(hash_counts),
            "dga_candidates": dga_hits,
            "recurring_hashes": recurring,
        },
    )


# Register with tool registry
tool_registry.register("incident_response.threat_hunting", run, metadata={
    "name": "incident_response.threat_hunting",
    "domain": "incident_response",
    "status": "completed",
    "description": "incident_response tool: hunts a local telemetry/artifact file for "
                    "high-entropy (likely-DGA) domains and recurring hash indicators; requires "
                    "`target` to be a local file path, not a network target",
    "parameters": {
        "target": "Local path to a telemetry/case-artifact file to hunt through (not a domain/IP/URL)",
    },
})
