#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.github_recon
Domain: reconnaissance

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to GitHub at all). Caught
during a follow-up audit. Now performs a real, unauthenticated call to
GitHub's public code-search REST API for real code/repo references to the
target domain — a real, free technique for finding leaked config files,
hardcoded internal hostnames, or credentials referencing the target.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_TOOL_NAME = "reconnaissance.github_recon"
_USER_AGENT = "NEXUS-STRIKE/0.2.0 (GithubRecon)"
_MAX_FINDINGS = 20


def run(target: str, **kwargs: Any) -> dict:
    """Real, unauthenticated GitHub code-search for references to the target domain."""
    domain = target.strip().lower()
    if not domain:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error="Empty target")

    token = kwargs.get("github_token")
    query = urllib.parse.quote(f'"{domain}"')
    url = f"https://api.github.com/search/code?q={query}&per_page=30"
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        ctx = get_ssl_context("api.github.com")
        resp = safe_urlopen(req, timeout=12, context=ctx)
        body = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return tool_result(
                _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
                summary="GitHub API rate limit hit on unauthenticated search "
                        "(10 req/min without a token) — pass github_token for higher limits",
                error=f"HTTP 403: {e.reason}",
            )
        if e.code == 422:
            return tool_result(
                _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
                summary=f"GitHub rejected the search query for '{domain}' (422) — likely too short/generic",
            )
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE, error=f"GitHub API HTTP {e.code}: {e.reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE, error=f"GitHub API unreachable: {e}")
    except (json.JSONDecodeError, ValueError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"unparseable GitHub response: {e}")

    items = body.get("items", []) if isinstance(body, dict) else []
    total_count = body.get("total_count", 0) if isinstance(body, dict) else 0

    if not items:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"No public GitHub code results reference '{domain}'",
        )

    findings: list[Finding] = []
    for item in items[:_MAX_FINDINGS]:
        repo = (item.get("repository") or {}).get("full_name", "unknown/unknown")
        path = item.get("path", "unknown")
        html_url = item.get("html_url", "")
        findings.append(Finding(
            title=f"Public GitHub code reference to '{domain}' in {repo}",
            severity="info",
            confidence="medium",
            affected_asset=domain,
            evidence=f"File {path} in repository {repo} matched a code search for '{domain}': {html_url}",
            remediation="Review the referencing file for exposed internal hostnames, credentials, "
                        "API keys, or configuration that shouldn't be public.",
            tool=_TOOL_NAME,
            references=[html_url] if html_url else ["CWE-200"],
        ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"GitHub code search for '{domain}' found {total_count} total result(s), "
                f"showing {len(findings)}",
        metadata={"total_count": total_count},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Real, unauthenticated GitHub code-search for public references to the target domain "
                    "(leaked configs, hardcoded hostnames/credentials)",
    "parameters": {
        "target": "Target domain to search GitHub public code for",
        "github_token": "(optional) GitHub personal access token for higher rate limits",
    },
})
