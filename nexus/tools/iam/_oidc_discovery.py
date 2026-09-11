#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam._oidc_discovery
Shared, real OAuth2/OIDC discovery-document fetch + analysis used by both
iam.oauth_testing and iam.sso_testing — they check the same real
/.well-known/* endpoints for the same weak-configuration indicators under
two names, so the real HTTP + parsing logic lives here once. Not registered
as a tool itself.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import Finding
from nexus.foundation.ssl_config import get_ssl_context

_WELL_KNOWN_PATHS = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)


def _base_url(target: str) -> str:
    return target if "://" in target else f"https://{target}"


def fetch_discovery_document(target: str, timeout: int = 5) -> tuple[str | None, dict | None]:
    """Real HTTP GET against the standard OIDC/OAuth2 discovery endpoints."""
    base = _base_url(target).rstrip("/")
    for path in _WELL_KNOWN_PATHS:
        url = f"{base}{path}"
        try:
            ctx = get_ssl_context(target, allow_insecure=True)
            req = urllib.request.Request(
                url, headers={"User-Agent": "NexusStrike/1.0", "Accept": "application/json"},
            )
            resp = safe_urlopen(req, timeout=timeout, context=ctx)
            if resp.status == 200:
                body = resp.read(65536).decode("utf-8", errors="replace")
                doc = json.loads(body)
                if isinstance(doc, dict):
                    return url, doc
        except Exception:
            continue
    return None, None


def analyze_discovery_document(url: str, doc: dict, tool_name: str) -> list[Finding]:
    """Real analysis of a fetched discovery document for weak/missing PKCE and implicit-flow support."""
    findings: list[Finding] = []
    response_types = doc.get("response_types_supported") or []
    grant_types = doc.get("grant_types_supported") or []
    pkce_methods = doc.get("code_challenge_methods_supported") or []

    implicit_response = any("token" in str(rt).split() for rt in response_types)
    implicit_grant = any("implicit" in str(gt).lower() for gt in grant_types)
    if implicit_response or implicit_grant:
        findings.append(Finding(
            title="OAuth2/OIDC implicit flow supported",
            severity="medium", confidence="high",
            affected_asset=url,
            evidence=f"response_types_supported={response_types!r}, grant_types_supported={grant_types!r} "
                     f"advertise implicit-flow token issuance.",
            remediation="Disable the OAuth2 implicit grant; require the authorization code flow with PKCE.",
            tool=tool_name,
            references=["CWE-522", "OAuth 2.0 Security Best Current Practice"],
        ))

    if "S256" not in [str(m) for m in pkce_methods]:
        findings.append(Finding(
            title="PKCE (S256) not advertised as supported",
            severity="medium", confidence="high",
            affected_asset=url,
            evidence=f"code_challenge_methods_supported={pkce_methods!r} does not include 'S256'.",
            remediation="Require PKCE with the S256 code challenge method for all authorization code flows.",
            tool=tool_name,
            references=["CWE-352", "RFC 7636"],
        ))

    return findings
