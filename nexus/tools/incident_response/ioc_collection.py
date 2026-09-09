#!/usr/bin/env python3
"""
NEXUS-STRIKE — incident_response tool: Ioc Collection
Domain: incident_response

Collecting indicators of compromise means extracting IPs/hashes/domains
that already exist in case artifacts (a memory dump string, a proxy log,
an analyst's notes) — it needs that artifact, not a network probe. This
previously hashed `target` as if it were a file on disk (it never was —
`target` is a domain/IP/URL) and hardcoded a check for the literal
substrings "malware"/"backdoor"/"trojan"/"keylog"/"ransom"/"exploit",
always reporting status "completed" even when the "is this a file" check
failed — caught during this session's audit.

Now: if `target` is a real local file, this does genuine IOC extraction —
regex-extraction of IPv4/IPv6 addresses, MD5/SHA1/SHA256 hashes, domains,
and URLs from the file's text, with real shape validation (IPv4 octet
range, minimum domain label/TLD structure) rather than a hardcoded
substring list. If `target` isn't a readable file, it honestly reports
STATUS_OUT_OF_SCOPE instead of fabricating a hash of an unrelated string.
"""
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
_IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b')
_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?!\d+\b)[a-zA-Z]{2,24}\b'
)
_URL_RE = re.compile(r'\bhttps?://[^\s"\'<>\]\)]+', re.IGNORECASE)


def _extract_iocs(text: str) -> dict:
    # Hashes are checked longest-pattern-first and removed from the pool so
    # a 64-hex-char SHA256 doesn't also get double-counted as containing a
    # 32-hex-char MD5 substring match.
    sha256 = sorted(set(_SHA256_RE.findall(text)))
    remaining = _SHA256_RE.sub(" ", text)
    sha1 = sorted(set(_SHA1_RE.findall(remaining)))
    remaining = _SHA1_RE.sub(" ", remaining)
    md5 = sorted(set(_MD5_RE.findall(remaining)))

    urls = sorted(set(_URL_RE.findall(text)))
    ipv4 = sorted(set(_IPV4_RE.findall(text)))
    ipv6 = sorted(set(m for m in _IPV6_RE.findall(text) if m.count(":") >= 2))
    domains = sorted(set(_DOMAIN_RE.findall(text)) - set(ipv4))

    return {
        "ipv4": ipv4, "ipv6": ipv6, "md5": md5, "sha1": sha1,
        "sha256": sha256, "domains": domains, "urls": urls,
    }


def run(target: str, **kwargs) -> dict:
    """incident_response tool: Ioc Collection"""
    if not os.path.isfile(target):
        return tool_result(
            "incident_response.ioc_collection", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"IOC collection from {target} requires a real local case artifact (a log, "
                    f"memory-dump string export, or analyst notes file) to extract indicators "
                    f"from — a bare domain/IP/URL has no IOCs embedded in it to collect",
            error="requires_case_data: target is not a readable local file path",
            metadata={"requires": ["a local case-artifact file path as `target`"]},
        )

    try:
        if os.path.getsize(target) > _MAX_BYTES:
            return tool_result(
                "incident_response.ioc_collection", target, status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} exceeds this tool's {_MAX_BYTES}-byte extraction cap",
                error="requires_case_data: file too large for inline extraction",
            )
        with open(target, "r", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return tool_result(
            "incident_response.ioc_collection", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    iocs = _extract_iocs(text)
    total = sum(len(v) for v in iocs.values())

    findings = []
    for kind, values in iocs.items():
        if values:
            findings.append(Finding(
                title=f"{len(values)} {kind.upper()} indicator(s) extracted",
                severity="info",
                confidence="high",
                affected_asset=target,
                evidence=", ".join(values[:10]) + (" ..." if len(values) > 10 else ""),
                remediation="Cross-reference extracted indicators against threat-intel feeds "
                             "before acting on them.",
            ))

    status = STATUS_COMPLETED if total else STATUS_NO_FINDINGS
    return tool_result(
        "incident_response.ioc_collection", target, status=status, findings=findings,
        summary=f"Extracted {total} unique indicator(s) from {target}: "
                + ", ".join(f"{len(v)} {k}" for k, v in iocs.items() if v),
        metadata={"ioc_counts": {k: len(v) for k, v in iocs.items()}, "iocs": iocs},
    )


# Register with tool registry
tool_registry.register("incident_response.ioc_collection", run, metadata={
    "name": "incident_response.ioc_collection",
    "domain": "incident_response",
    "status": "completed",
    "description": "incident_response tool: regex-extracts and shape-validates IOCs "
                    "(IPv4/IPv6, MD5/SHA1/SHA256 hashes, domains, URLs) from a local case "
                    "artifact file; requires `target` to be a local file path, not a network target",
    "parameters": {
        "target": "Local path to a case-artifact file to extract IOCs from (not a domain/IP/URL)",
    },
})
