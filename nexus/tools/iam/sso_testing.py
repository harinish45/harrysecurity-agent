#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam.sso_testing
Domain: iam
Real network check for SSO's underlying OAuth2/OIDC discovery endpoints
(/.well-known/openid-configuration, /.well-known/oauth-authorization-server)
via safe_urlopen; real JSON parsing of any discovery document found for
weak/missing PKCE support and implicit-flow token issuance — the same
protocol surface iam.oauth_testing checks, framed for an SSO identity
provider.

Previously this was a bare DNS resolve + a handful of unauthenticated GETs
against generic paths like /login, /admin (byte-for-byte identical to 19
other stub tools, and none of it actually SSO-specific) — caught during
this session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, STATUS_NO_FINDINGS, tool_result
from nexus.tools.iam._oidc_discovery import analyze_discovery_document, fetch_discovery_document
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs: Any) -> dict:
    """Real OIDC discovery-document fetch and weak-configuration analysis for an SSO identity provider.

    Parameters
    ----------
    target : str
        Hostname or URL of the SSO identity provider.
    """
    tool_name = "iam.sso_testing"
    if not target or not target.strip():
        return tool_result(tool_name, target, status=STATUS_FAILED, error="Empty target")

    url, doc = fetch_discovery_document(target)
    if not doc:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"No OIDC discovery document found at {target}'s well-known endpoints "
                    f"(/.well-known/openid-configuration, /.well-known/oauth-authorization-server) — "
                    f"this SSO provider may use SAML instead (see iam.saml_testing).",
        )

    findings = analyze_discovery_document(url, doc, tool_name)
    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Real OIDC discovery document fetched from {url}; {len(findings)} issue(s) found.",
        metadata={"discovery_url": url, "issuer": doc.get("issuer")},
    )


tool_registry.register("iam.sso_testing", run, metadata={
    "name": "iam.sso_testing",
    "domain": "iam",
    "status": "completed",
    "description": "Real SSO/OIDC discovery-endpoint check for weak PKCE support and implicit-flow token issuance",
    "parameters": {
        "target": "Hostname or URL of the SSO identity provider",
    },
})
