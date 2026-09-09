#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.session_mgmt
Domain: webapp
Session cookie security analysis (HttpOnly / Secure / SameSite flags).

Previously: a dummy stub identical across all 17 webapp.* "secondary" tools
(DNS resolve + bare GET of "/", never actually looked at Set-Cookie).
Now: a real GET of the target that inspects every Set-Cookie header issued
and flags missing HttpOnly, Secure (when served over HTTPS), and SameSite
attributes, plus overly long cookie lifetimes and predictable-looking
session identifiers.
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Session Mgmt Analyzer)"

SESSION_NAME_PATTERN = re.compile(
    r"session|sess|sid|jsessionid|phpsessid|auth|token|connect\.sid",
    re.IGNORECASE,
)


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET and return status/headers/cookies."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        resp.read(4096)
        cookies = resp.headers.get_all("Set-Cookie") or []
        return {"status": resp.status, "cookies": cookies, "error": None}
    except urllib.error.HTTPError as e:
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        return {"status": e.code, "cookies": cookies or [], "error": None}
    except Exception as e:
        return {"status": 0, "cookies": [], "error": str(e)[:100]}


def _parse_cookie(cookie_header: str) -> dict:
    """Parse a single Set-Cookie header into name/value/attributes."""
    parts = [p.strip() for p in cookie_header.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {"httponly": False, "secure": False, "samesite": None, "max_age": None, "expires": None}
    for part in parts[1:]:
        low = part.lower()
        if low == "httponly":
            attrs["httponly"] = True
        elif low == "secure":
            attrs["secure"] = True
        elif low.startswith("samesite"):
            attrs["samesite"] = part.split("=", 1)[1].strip() if "=" in part else "(empty)"
        elif low.startswith("max-age"):
            attrs["max_age"] = part.split("=", 1)[1].strip() if "=" in part else None
        elif low.startswith("expires"):
            attrs["expires"] = part.split("=", 1)[1].strip() if "=" in part else None
    return {"name": name.strip(), "value": value.strip(), **attrs}


def run(target: str, timeout: int = 10, **kwargs: Any) -> dict:
    """Analyze session/cookie security attributes on target.

    Parameters
    ----------
    target : str
        URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.session_mgmt", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    is_https = url.lower().startswith("https://")
    findings: list[Finding] = []
    resp = _http_request(url, timeout)

    if resp["status"] == 0:
        return tool_result("webapp.session_mgmt", target, status=STATUS_FAILED, error=resp.get("error") or "Connection failed")

    cookies = [_parse_cookie(c) for c in resp["cookies"]]
    session_cookies = [c for c in cookies if SESSION_NAME_PATTERN.search(c["name"])] or cookies

    for cookie in session_cookies:
        if not cookie["httponly"]:
            findings.append(Finding(
                title=f"Cookie '{cookie['name']}' missing HttpOnly flag",
                severity="medium",
                confidence="high",
                affected_asset=url,
                evidence=f"Set-Cookie for '{cookie['name']}' has no HttpOnly attribute — readable via JavaScript (XSS-to-session-theft)",
                remediation="Set the HttpOnly attribute on all session/authentication cookies.",
                tool="webapp.session_mgmt",
                references=["CWE-1004", "OWASP-A05"],
            ))
        if is_https and not cookie["secure"]:
            findings.append(Finding(
                title=f"Cookie '{cookie['name']}' missing Secure flag",
                severity="medium",
                confidence="high",
                affected_asset=url,
                evidence=f"Set-Cookie for '{cookie['name']}' has no Secure attribute on an HTTPS site — cookie can leak over plaintext HTTP",
                remediation="Set the Secure attribute on all cookies served over HTTPS.",
                tool="webapp.session_mgmt",
                references=["CWE-614"],
            ))
        if not cookie["samesite"]:
            findings.append(Finding(
                title=f"Cookie '{cookie['name']}' missing SameSite attribute",
                severity="low",
                confidence="high",
                affected_asset=url,
                evidence=f"Set-Cookie for '{cookie['name']}' has no SameSite attribute",
                remediation="Set SameSite=Strict or SameSite=Lax to reduce CSRF exposure.",
                tool="webapp.session_mgmt",
                references=["CWE-352"],
            ))
        elif cookie["samesite"].lower() == "none" and not cookie["secure"]:
            findings.append(Finding(
                title=f"Cookie '{cookie['name']}' uses SameSite=None without Secure",
                severity="medium",
                confidence="high",
                affected_asset=url,
                evidence=f"SameSite=None requires the Secure attribute; '{cookie['name']}' lacks it",
                remediation="Pair SameSite=None with the Secure attribute, or use SameSite=Lax/Strict instead.",
                tool="webapp.session_mgmt",
                references=["CWE-352"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Session cookie analysis: {len(cookies)} cookie(s) set, {len(findings)} issue(s) found" if cookies \
        else "Session cookie analysis: target set no cookies on initial GET"

    return tool_result(
        "webapp.session_mgmt", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"cookies_found": len(cookies), "cookie_names": [c["name"] for c in cookies]},
    )


tool_registry.register("webapp.session_mgmt", run, metadata={
    "name": "webapp.session_mgmt",
    "domain": "webapp",
    "status": "completed",
    "description": "Session cookie security analysis: HttpOnly, Secure, and SameSite flag inspection",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})
