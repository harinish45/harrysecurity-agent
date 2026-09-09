#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.authorization_test
Domain: webapp
Authorization / access-control testing (privilege enforcement).

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", never touched a privileged path).
Now: real unauthenticated GETs of common privileged-looking paths
(/admin, /api/admin, /dashboard, /account, /settings, ...), classifying
each response as properly gated (401/403, or a redirect to a login page)
vs. a broken-access-control indicator (a plain HTTP 200 with no
authentication challenge or login redirect). This is authorization (what
an identity is *allowed to do*); its sibling webapp.auth_test checks how
the application verifies *who you are* — a genuinely different check,
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Authorization Tester)"

PRIVILEGED_PATHS = [
    "/admin", "/admin/", "/administrator", "/api/admin", "/dashboard",
    "/account", "/settings", "/manage", "/management", "/console",
    "/wp-admin/", "/cpanel", "/api/internal", "/internal",
]

LOGIN_REDIRECT_PATTERN = re.compile(r"login|signin|sign-in|auth", re.IGNORECASE)


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET (no redirect auto-follow analysis needed —
    urllib follows redirects itself, so we inspect the final URL reached)."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(16384).decode("utf-8", errors="replace")
        final_url = resp.geturl()
        return {
            "status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()},
            "body": body, "final_url": final_url, "error": None,
        }
    except urllib.error.HTTPError as e:
        body = e.read(16384).decode("utf-8", errors="replace") if e.fp else ""
        return {
            "status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
            "body": body, "final_url": e.geturl() if hasattr(e, "geturl") else url, "error": None,
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "final_url": url, "error": str(e)[:100]}


def run(target: str, timeout: int = 10, paths: list[str] | None = None, **kwargs: Any) -> dict:
    """Test whether privileged-looking paths are properly access-controlled.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    paths : list[str], optional
        Custom list of privileged paths to try.
    """
    if not target or not target.strip():
        return tool_result("webapp.authorization_test", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []
    checked: list[dict] = []

    for path in (paths or PRIVILEGED_PATHS):
        endpoint = f"{root}{path}"
        resp = _http_request(endpoint, timeout)
        if resp["status"] == 0:
            continue

        properly_gated = (
            resp["status"] in (401, 403)
            or LOGIN_REDIRECT_PATTERN.search(resp.get("final_url", "") or "")
            or "www-authenticate" in resp["headers"]
        )
        exposed = resp["status"] == 200 and not properly_gated

        checked.append({
            "path": path, "url": endpoint, "status": resp["status"],
            "final_url": resp.get("final_url"), "properly_gated": properly_gated,
        })

        if exposed:
            findings.append(Finding(
                title=f"Privileged path reachable without authentication: {path}",
                severity="high",
                confidence="medium",
                affected_asset=endpoint,
                evidence=(
                    f"Unauthenticated GET {endpoint} returned HTTP {resp['status']} directly "
                    f"(final URL: {resp.get('final_url')}) — no 401/403 and no redirect to a login page"
                ),
                remediation="Enforce server-side authorization checks on this path; do not rely on the path being unlinked/undiscoverable.",
                tool="webapp.authorization_test",
                references=["CWE-284", "CWE-862", "OWASP-A01"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    exposed_count = len(findings)
    summary = f"Authorization testing: {len(checked)} privileged path(s) checked, {exposed_count} reachable without authentication"

    return tool_result(
        "webapp.authorization_test", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"checked": checked},
    )


tool_registry.register("webapp.authorization_test", run, metadata={
    "name": "webapp.authorization_test",
    "domain": "webapp",
    "status": "completed",
    "description": "Authorization/access-control testing: unauthenticated probing of privileged-looking paths for broken access control",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "paths": "Custom list of privileged paths to try",
    },
})
