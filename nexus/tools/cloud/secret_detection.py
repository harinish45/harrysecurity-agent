#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.secret_detection
Domain: cloud

This previously ignored `target` entirely and did a DNS resolve + bare HTTP
GET on `/` against it — byte-for-byte identical to eight other "cloud"
stubs, none of which had anything to do with secret detection. Caught
during this session's audit. nexus/tools/appsec/secret_scanning.py already
implements real regex-based secret scanning (AWS keys, GitHub/OpenAI/Slack
tokens, PEM private key headers, generic api_key/password/secret patterns)
against a local file or directory. Rather than duplicate that pattern set
and file-walking logic here, this delegates to it directly and simply
relabels the result under the `cloud.secret_detection` tool name — this is
the "cloud-focused" entry point (e.g. scanning a checked-out IaC/config repo
for leaked cloud credentials specifically), while appsec.secret_scanning
remains the general-purpose source-code scanner.
"""
from __future__ import annotations

from typing import Any

from nexus.tools.appsec import secret_scanning as _appsec_secret_scanning
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs: Any) -> dict:
    """Regex-based secret scan of a local file or directory (delegates to
    appsec.secret_scanning; see that module's SECRET_PATTERNS for the full
    detection list: AWS keys, GitHub/OpenAI/Google/Slack tokens, PEM private
    key headers, generic api_key/password/secret key=value pairs).

    Parameters
    ----------
    target : str
        Path to a local file or directory to scan. Not a hostname/URL.
    """
    result = _appsec_secret_scanning.run(target, **kwargs)
    result["tool"] = "cloud.secret_detection"
    for finding in result.get("findings", []):
        if finding.get("tool") == "appsec.secret_scanning":
            finding["tool"] = "cloud.secret_detection"
    return result


tool_registry.register("cloud.secret_detection", run, metadata={
    "name": "cloud.secret_detection",
    "domain": "cloud",
    "status": "completed",
    "description": "Regex-based secret/credential scan of a local file or directory (delegates to appsec.secret_scanning's real detection patterns: AWS keys, tokens, private keys, generic secrets)",
    "parameters": {
        "target": "Path to a local file or directory to scan",
        "max_size_mb": "Skip files larger than this size (default: 10MB)",
    },
})
