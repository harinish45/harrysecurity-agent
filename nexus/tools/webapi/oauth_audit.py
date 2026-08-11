#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapi.oauth_audit
Domain: webapi
OAuth/OIDC misconfiguration scanner: state param, redirect URI validation, PKCE, token handling.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
import urllib.parse
import urllib.error
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry


def _http_get(url: str, timeout: int = 10) -> dict:
    """Perform a GET and return {'status', 'body', 'headers', 'final_url'}."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/1.0.0 (OAuth Auditor)"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {
            "status": resp.status,
            "body": body,
            "headers": dict(resp.headers),
            "final_url": resp.geturl(),
        }
    except urllib.error.HTTPError as e:
        body = (e.read(65536).decode("utf-8", errors="replace") if e.fp else "") or ""
        return {"status": e.code, "body": body, "headers": dict(e.headers), "final_url": e.geturl() if hasattr(e, "geturl") else url}
    except Exception as exc:
        return {"status": 0, "body": "", "headers": {}, "final_url": url, "error": str(exc)[:100]}


def _discover_provider(target: str, timeout: int = 10) -> dict:
    """Attempt to discover OAuth/OIDC endpoints from .well-known/openid-configuration."""
    base = target if "://" in target else f"https://{target}"
    candidates = [
        f"{base.rstrip('/')}/.well-known/openid-configuration",
        f"{base.rstrip('/')}/.well-known/oauth-authorization-server",
        f"{base.rstrip('/')}/oidc/.well-known/openid-configuration",
    ]
    for cand in candidates:
        resp = _http_get(cand, timeout)
        if resp["status"] == 200:
            try:
                data = json.loads(resp["body"])
                if isinstance(data, dict) and ("authorization_endpoint" in data or "token_endpoint" in data):
                    return {"discovered": True, "config_url": cand, "config": data}
            except json.JSONDecodeError:
                pass
    return {"discovered": False, "config_url": None, "config": {}}


def run(
    target: str,
    client_id: str = None,
    redirect_uri: str = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict:
    """Audit an OAuth/OIDC authorization server for common misconfigurations.

    Parameters
    ----------
    target : str
        Base URL of the OAuth/OIDC provider (host or full URL).
    client_id : str, optional
        A known OAuth client ID for the client-registration tests.
    redirect_uri : str, optional
        A valid redirect URI to use as the baseline.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapi.oauth_audit", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    results: list[dict] = []

    # ── Phase 1: Discover provider endpoints ────────────────────────────────
    provider = _discover_provider(target, timeout)
    auth_endpoint = provider["config"].get("authorization_endpoint", "")
    token_endpoint = provider["config"].get("token_endpoint", "")
    code_challenge_methods = provider["config"].get("code_challenge_methods_supported", [])
    response_types = provider["config"].get("response_types_supported", [])
    grant_types = provider["config"].get("grant_types_supported", [])

    results.append({"test": "discovery", "config_url": provider["config_url"]})

    # ── Phase 2: Verify auth endpoint behavior ──────────────────────────────
    base = target if "://" in target else f"https://{target}"
    if not auth_endpoint:
        # Fall back to common paths
        auth_endpoint = f"{base.rstrip('/')}/oauth/authorize"
        token_endpoint = f"{base.rstrip('/')}/oauth/token"

    # 2a. Build an authorization URL without state and see if the server
    #     proceeds (a 302/200 to the redirect URI indicates missing state enforcement).
    test_redirect = redirect_uri or f"{base.rstrip('/')}/callback"
    params = {
        "response_type": "code",
        "client_id": client_id or "test-client-id",
        "redirect_uri": test_redirect,
    }
    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
    resp = _http_get(auth_url, timeout)
    if resp["status"] in (200, 302, 303):
        # If we get a redirect to the callback, the server accepted a request without state
        if resp["final_url"] != auth_url and ("state" not in urllib.parse.urlparse(auth_url).query):
            findings.append(Finding(
                title="OAuth authorization request missing CSRF 'state' parameter",
                severity="high",
                confidence="medium",
                affected_asset=auth_endpoint,
                evidence=(
                    f"Authorization request without 'state' was accepted and redirected "
                    f"({resp['final_url'][:120]})"
                ),
                remediation="Require a cryptographically random 'state' parameter on all authorization requests.",
                tool="webapi.oauth_audit",
                references=["CWE-352", "OWASP-API1"],
            ))
            results.append({"test": "state_csrf", "vulnerable": True, "final_url": resp["final_url"]})
        else:
            results.append({"test": "state_csrf", "vulnerable": False})

    # 2b. Redirect URI validation — try an open redirect / token-theft variant
    evil_redirect = "https://evil.example.com/callback"
    params_open = {
        "response_type": "code",
        "client_id": client_id or "test-client-id",
        "redirect_uri": evil_redirect,
    }
    open_url = f"{auth_endpoint}?{urllib.parse.urlencode(params_open)}"
    resp_open = _http_get(open_url, timeout)
    if resp_open["status"] in (200, 302, 303):
        final_redirect = resp_open["final_url"]
        if "evil.example.com" in final_redirect or "evil.example.com" in urllib.parse.unquote(final_redirect):
            findings.append(Finding(
                title="OAuth redirect_uri not validated (open redirect / token theft)",
                severity="critical",
                confidence="high",
                affected_asset=auth_endpoint,
                evidence=f"Authorization request with redirect_uri={evil_redirect} was accepted and redirected to it",
                remediation="Strictly validate redirect_uri against an exact allow-list of registered URIs.",
                tool="webapi.oauth_audit",
                references=["CWE-601", "OWASP-API2"],
            ))
            results.append({"test": "redirect_uri_validation", "vulnerable": True})
        else:
            results.append({"test": "redirect_uri_validation", "vulnerable": False})

    # 2c. Token-in-fragment handling — check if the callback page references access_token in URL fragment
    callback_resp = _http_get(test_redirect, timeout)
    if callback_resp["status"] == 200:
        body_lower = callback_resp["body"].lower()
        if "access_token" in body_lower and "#" in callback_resp["final_url"]:
            findings.append(Finding(
                title="OAuth access token in URL fragment (implicit flow)",
                severity="medium",
                confidence="medium",
                affected_asset=test_redirect,
                evidence="Callback page references access_token in the URL fragment",
                remediation="Use the authorization code + PKCE flow instead of the implicit flow.",
                tool="webapi.oauth_audit",
                references=["CWE-598", "OWASP-API3"],
            ))
            results.append({"test": "token_in_fragment", "vulnerable": True})
        else:
            results.append({"test": "token_in_fragment", "vulnerable": False})

    # ── Phase 3: PKCE enforcement ──────────────────────────────────────────
    if provider["discovered"]:
        if code_challenge_methods:
            results.append({"test": "pkce_supported", "methods": code_challenge_methods})
            if "S256" not in code_challenge_methods:
                findings.append(Finding(
                    title="OAuth server does not support PKCE with S256",
                    severity="medium",
                    confidence="high",
                    affected_asset=provider["config_url"],
                    evidence=f"code_challenge_methods_supported={code_challenge_methods}",
                    remediation="Enable PKCE S256 support and require it for public clients.",
                    tool="webapi.oauth_audit",
                    references=["CWE-294", "OWASP-API3"],
                ))
        # Check if PKCE is required by inspecting if authorization request without
        # code_challenge is rejected
        params_nopkce = {
            "response_type": "code",
            "client_id": client_id or "test-client-id",
            "redirect_uri": test_redirect,
            "state": "st",
        }
        nopkce_url = f"{auth_endpoint}?{urllib.parse.urlencode(params_nopkce)}"
        resp_nopkce = _http_get(nopkce_url, timeout)
        # If the server accepts a PKCE-less request, it doesn't enforce PKCE
        if resp_nopkce["status"] in (302, 303) or (resp_nopkce["status"] == 200 and "code" not in resp_nopkce["body"].lower()):
            results.append({"test": "pkce_enforced", "vulnerable": False})
        else:
            results.append({"test": "pkce_enforced", "vulnerable": True})
    else:
        results.append({"test": "pkce_supported", "discovered": False})

    # ── Phase 4: Response type / grant type audit ──────────────────────────
    if response_types:
        if "token" in response_types:
            findings.append(Finding(
                title="OAuth implicit flow response_type='token' enabled",
                severity="low",
                confidence="high",
                affected_asset=provider["config_url"],
                evidence=f"response_types_supported includes 'token' ({response_types})",
                remediation="Disable the implicit flow; require authorization code + PKCE.",
                tool="webapi.oauth_audit",
                references=["CWE-598", "OWASP-API3"],
            ))
            results.append({"test": "implicit_flow", "enabled": True})
        else:
            results.append({"test": "implicit_flow", "enabled": False})
    else:
        results.append({"test": "response_types", "not_discovered": True})

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"OAuth/OIDC audit on {base}: {len(findings)} issue(s) found"
    return tool_result(
        "webapi.oauth_audit",
        target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"provider": provider, "results": results},
    )


tool_registry.register("webapi.oauth_audit", run, metadata={
    "name": "webapi.oauth_audit",
    "domain": "webapi",
    "status": "completed",
    "description": "OAuth/OIDC misconfiguration scanner: state, redirect URI, PKCE, implicit flow",
    "parameters": {
        "target": "OAuth provider base URL",
        "client_id": "Known OAuth client ID (optional)",
        "redirect_uri": "Valid redirect URI (optional)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})