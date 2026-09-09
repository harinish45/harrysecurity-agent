#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.auth_test
Domain: webapp
Authentication mechanism testing (identity verification).

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", never touched an auth endpoint).
Now: real probes of common login/auth endpoints (/login, /api/login,
/signin, ...) to confirm how the application authenticates callers — HTTP
Basic/Digest challenge (WWW-Authenticate) vs. a form-based login page — and
whether credentials would travel in plaintext (an http:// login form
action). This is authentication (proving *who you are*); its sibling
webapp.authorization_test checks access control on already-privileged
paths (what an identity is *allowed to do*) — a genuinely different check,
not a duplicate.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import re
import urllib.error
import urllib.request
import urllib.parse
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Auth Mechanism Tester)"

LOGIN_PATHS = [
    "/login", "/api/login", "/signin", "/sign-in", "/auth/login",
    "/api/auth/login", "/user/login", "/account/login", "/wp-login.php",
]

FORM_PATTERN = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
FORM_ACTION_PATTERN = re.compile(r"action\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)
PASSWORD_FIELD_PATTERN = re.compile(r"<input\b[^>]*type\s*=\s*['\"]password['\"]", re.IGNORECASE)


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET and return status/headers/body."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()}, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()}, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)[:100]}


def run(target: str, timeout: int = 10, paths: list[str] | None = None, **kwargs: Any) -> dict:
    """Test how target authenticates callers.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    paths : list[str], optional
        Custom list of login endpoint paths to try.
    """
    if not target or not target.strip():
        return tool_result("webapp.auth_test", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    is_https = parsed.scheme == "https"

    findings: list[Finding] = []
    login_endpoints: list[dict] = []

    root_resp = _http_request(root, timeout)
    if root_resp["status"] == 0:
        return tool_result("webapp.auth_test", target, status=STATUS_FAILED, error=root_resp.get("error") or "Connection failed")

    if root_resp["status"] == 401 and "www-authenticate" in root_resp["headers"]:
        scheme = root_resp["headers"]["www-authenticate"].split(" ")[0]
        findings.append(Finding(
            title=f"HTTP {scheme} authentication challenge on root",
            severity="info",
            confidence="certain",
            affected_asset=root,
            evidence=f"WWW-Authenticate: {root_resp['headers']['www-authenticate']}",
            remediation="Confirm HTTP Basic/Digest auth is intended; prefer a modern session/token-based scheme with rate limiting and MFA support.",
            tool="webapp.auth_test",
            references=["CWE-522"] if scheme.lower() == "basic" and not is_https else [],
        ))
        if scheme.lower() == "basic" and not is_https:
            findings.append(Finding(
                title="HTTP Basic authentication offered over plaintext HTTP",
                severity="high",
                confidence="high",
                affected_asset=root,
                evidence="WWW-Authenticate: Basic realm=... served over http:// — credentials are base64, not encrypted",
                remediation="Serve authentication exclusively over HTTPS; redirect all HTTP traffic to HTTPS.",
                tool="webapp.auth_test",
                references=["CWE-319", "CWE-522"],
            ))

    for path in (paths or LOGIN_PATHS):
        endpoint = f"{root}{path}"
        resp = _http_request(endpoint, timeout)
        if resp["status"] in (0, 404):
            continue

        has_password_field = bool(PASSWORD_FIELD_PATTERN.search(resp["body"]))
        has_form = bool(FORM_PATTERN.search(resp["body"]))
        if not (has_password_field or resp["status"] in (200, 401, 405)):
            continue

        login_endpoints.append({"path": path, "url": endpoint, "status": resp["status"], "has_password_field": has_password_field})

        findings.append(Finding(
            title=f"Login endpoint discovered: {path}",
            severity="info",
            confidence="high" if has_password_field else "medium",
            affected_asset=endpoint,
            evidence=f"HTTP {resp['status']}" + (" with a password input field" if has_password_field else ""),
            remediation="Confirm this endpoint enforces lockout/rate-limiting on repeated failed attempts (see webapp.rate_limit) and transmits credentials only over HTTPS.",
            tool="webapp.auth_test",
            references=[],
        ))

        if has_password_field and has_form and not is_https:
            action_m = FORM_ACTION_PATTERN.search(resp["body"])
            action = action_m.group(1) if action_m else ""
            action_url = urllib.parse.urljoin(endpoint, action) if action else endpoint
            if not action_url.lower().startswith("https://"):
                findings.append(Finding(
                    title=f"Login form at {path} submits over plaintext HTTP",
                    severity="critical",
                    confidence="high",
                    affected_asset=action_url,
                    evidence=f"Password field present in a form served/submitted over {parsed.scheme}:// — credentials travel unencrypted",
                    remediation="Serve the login page and its form action exclusively over HTTPS.",
                    tool="webapp.auth_test",
                    references=["CWE-319", "OWASP-A02"],
                ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Authentication mechanism testing: {len(login_endpoints)} login endpoint(s) found, {len(findings)} finding(s)"

    return tool_result(
        "webapp.auth_test", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"login_endpoints": login_endpoints},
    )


tool_registry.register("webapp.auth_test", run, metadata={
    "name": "webapp.auth_test",
    "domain": "webapp",
    "status": "completed",
    "description": "Authentication mechanism testing: login endpoint discovery, HTTP Basic/Digest challenge detection, plaintext-credential-transmission check",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "paths": "Custom list of login endpoint paths to try",
    },
})
