#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.csrf
Domain: webapp
Cross-Site Request Forgery (CSRF) protection analysis.

Previously: a dummy stub identical across all 17 webapp.* "secondary" tools
(DNS resolve + bare GET of "/", header-only checks, no CSRF-specific logic
whatsoever). Now: a real GET of the target, extraction of every HTML
<form>, and a check that each form carries a CSRF-token-shaped hidden field
(csrf, _token, authenticity_token, nonce, etc.); plus a real inspection of
every Set-Cookie header for the SameSite attribute, which is the other
primary CSRF mitigation.
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (CSRF Analyzer)"

# Hidden-field name patterns commonly used to carry anti-CSRF tokens.
CSRF_TOKEN_NAME_PATTERN = re.compile(
    r"csrf|xsrf|_token|authenticity_token|nonce|anti-forgery|requestverificationtoken",
    re.IGNORECASE,
)

FORM_PATTERN = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
FORM_METHOD_PATTERN = re.compile(r"method\s*=\s*['\"]?([a-zA-Z]+)", re.IGNORECASE)
FORM_ACTION_PATTERN = re.compile(r"action\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)
HIDDEN_INPUT_PATTERN = re.compile(
    r"<input\b[^>]*type\s*=\s*['\"]hidden['\"][^>]*>", re.IGNORECASE
)
NAME_ATTR_PATTERN = re.compile(r"name\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET and return status/headers/body."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(131072).decode("utf-8", errors="replace")
        cookies = resp.headers.get_all("Set-Cookie") or []
        return {"status": resp.status, "headers": dict(resp.headers), "cookies": cookies, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(131072).decode("utf-8", errors="replace") if e.fp else ""
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        return {"status": e.code, "headers": dict(e.headers or {}), "cookies": cookies or [], "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "cookies": [], "body": "", "error": str(e)[:100]}


def _forms_missing_csrf_token(html: str) -> list[dict]:
    """Return state-changing forms (POST/PUT/PATCH/DELETE) that have no
    hidden field whose name looks like a CSRF token."""
    missing = []
    for match in FORM_PATTERN.finditer(html):
        form_body = match.group(1)
        form_tag = html[match.start():match.start() + 300]
        method_m = FORM_METHOD_PATTERN.search(form_tag)
        method = (method_m.group(1).upper() if method_m else "GET")
        if method == "GET":
            continue  # GET forms don't need CSRF tokens
        action_m = FORM_ACTION_PATTERN.search(form_tag)
        action = action_m.group(1) if action_m else ""
        has_token = False
        for hidden in HIDDEN_INPUT_PATTERN.finditer(form_body):
            name_m = NAME_ATTR_PATTERN.search(hidden.group(0))
            if name_m and CSRF_TOKEN_NAME_PATTERN.search(name_m.group(1)):
                has_token = True
                break
        if not has_token:
            missing.append({"method": method, "action": action})
    return missing


def _cookie_missing_samesite(cookie_header: str) -> bool:
    return "samesite" not in cookie_header.lower()


def run(target: str, timeout: int = 10, **kwargs: Any) -> dict:
    """Analyze target for CSRF protection weaknesses.

    Parameters
    ----------
    target : str
        URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.csrf", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    resp = _http_request(url, timeout)

    if resp["status"] == 0:
        return tool_result("webapp.csrf", target, status=STATUS_FAILED, error=resp.get("error") or "Connection failed")

    forms_checked = len(FORM_PATTERN.findall(resp["body"]))
    missing_token_forms = _forms_missing_csrf_token(resp["body"])
    for form in missing_token_forms:
        findings.append(Finding(
            title=f"State-changing form without CSRF token ({form['method']} {form['action'] or url})",
            severity="medium",
            confidence="medium",
            affected_asset=urllib.parse.urljoin(url, form["action"]) if form["action"] else url,
            evidence=f"{form['method']} form has no hidden field matching a CSRF-token naming pattern",
            remediation="Add a per-session/per-request anti-CSRF token as a hidden form field and validate it server-side.",
            tool="webapp.csrf",
            references=["CWE-352", "OWASP-A01"],
        ))

    cookies_missing_samesite = [c for c in resp["cookies"] if _cookie_missing_samesite(c)]
    for cookie in cookies_missing_samesite:
        cookie_name = cookie.split("=", 1)[0].strip()
        findings.append(Finding(
            title=f"Cookie '{cookie_name}' missing SameSite attribute",
            severity="low",
            confidence="high",
            affected_asset=url,
            evidence=f"Set-Cookie: {cookie[:120]}",
            remediation="Set SameSite=Strict or SameSite=Lax on session cookies to mitigate CSRF.",
            tool="webapp.csrf",
            references=["CWE-352"],
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = (
        f"CSRF analysis: {forms_checked} form(s) found, {len(missing_token_forms)} missing tokens, "
        f"{len(resp['cookies'])} cookie(s) set, {len(cookies_missing_samesite)} missing SameSite"
    )

    return tool_result(
        "webapp.csrf", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={
            "forms_checked": forms_checked,
            "forms_missing_token": missing_token_forms,
            "cookies_checked": len(resp["cookies"]),
            "cookies_missing_samesite": len(cookies_missing_samesite),
        },
    )


tool_registry.register("webapp.csrf", run, metadata={
    "name": "webapp.csrf",
    "domain": "webapp",
    "status": "completed",
    "description": "CSRF protection analysis: form token presence and cookie SameSite attribute",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})
