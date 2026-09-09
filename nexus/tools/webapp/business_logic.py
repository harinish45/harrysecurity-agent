#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.business_logic
Domain: webapp
Business-logic validation testing: negative-value acceptance on numeric form fields.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no form/field analysis at all).
Now: a real GET of the target, extraction of HTML forms and their numeric
input fields (type="number", or names suggesting quantity/price/amount),
and a real submission of a negative value for each such field, checking
whether the server accepts it without any validation-rejection signal
(HTTP 200 and no error/invalid-shaped text in the response). If no
numeric field is found, this honestly reports no findings rather than
fabricating one.
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Business Logic Tester)"

FORM_PATTERN = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_PATTERN = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
ATTR_PATTERN = re.compile(r"(\w[\w-]*)\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)

NUMERIC_NAME_HINT = re.compile(r"qty|quantity|amount|price|total|count|units|num", re.IGNORECASE)

REJECTION_HINTS = re.compile(r"invalid|error|must be (?:a )?positive|cannot be negative|out of range|bad request", re.IGNORECASE)


def _http_request(url: str, timeout: int = 10, method: str = "GET", data: bytes = None, headers: dict | None = None) -> dict:
    """Make a real HTTP request and return status/body."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    try:
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(32768).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(32768).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)[:100]}


def _extract_numeric_fields(html: str, base_url: str) -> list[dict]:
    """Find forms with a numeric-shaped input field."""
    results = []
    for form_match in FORM_PATTERN.finditer(html):
        form_attrs = {m.group(1).lower(): m.group(2) for m in ATTR_PATTERN.finditer(form_match.group(1))}
        method = form_attrs.get("method", "GET").upper()
        action = urllib.parse.urljoin(base_url, form_attrs.get("action", ""))
        body = form_match.group(2)

        field_names = {}
        for inp_match in INPUT_PATTERN.finditer(body):
            attrs = {m.group(1).lower(): m.group(2) for m in ATTR_PATTERN.finditer(inp_match.group(1))}
            name = attrs.get("name")
            if not name:
                continue
            field_names[name] = attrs.get("value", "1")
            input_type = attrs.get("type", "text").lower()
            is_numeric = input_type == "number" or bool(NUMERIC_NAME_HINT.search(name))
            if is_numeric:
                results.append({
                    "method": method, "action": action, "field": name,
                    "all_fields": field_names, "input_type": input_type,
                })
    return results


def run(target: str, timeout: int = 10, negative_value: str = "-1", **kwargs: Any) -> dict:
    """Test numeric form fields for acceptance of negative values.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    negative_value : str
        Negative value to submit for each discovered numeric field.
    """
    if not target or not target.strip():
        return tool_result("webapp.business_logic", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []

    baseline = _http_request(base_url, timeout)
    if baseline["status"] == 0:
        return tool_result("webapp.business_logic", target, status=STATUS_FAILED, error=baseline.get("error") or "Connection failed")

    numeric_fields = _extract_numeric_fields(baseline["body"], base_url)
    if not numeric_fields:
        return tool_result(
            "webapp.business_logic", target,
            status=STATUS_NO_FINDINGS,
            summary="No form with a numeric-shaped input field (type=number, or name matching qty/quantity/amount/price/total/count) was found on the target page — nothing to test for negative-value acceptance.",
            metadata={"forms_with_numeric_fields": 0},
        )

    tested: list[dict] = []
    # Deduplicate by (method, action, field) — a page can list the same form target repeatedly.
    seen = set()
    for entry in numeric_fields:
        key = (entry["method"], entry["action"], entry["field"])
        if key in seen:
            continue
        seen.add(key)

        submitted = dict(entry["all_fields"])
        submitted[entry["field"]] = negative_value

        if entry["method"] == "GET":
            parsed = urllib.parse.urlparse(entry["action"])
            query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            query.update(submitted)
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
            resp = _http_request(test_url, timeout, method="GET")
        else:
            encoded = urllib.parse.urlencode(submitted).encode("utf-8")
            resp = _http_request(
                entry["action"], timeout, method="POST", data=encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        accepted = resp["status"] in (200, 201, 202, 302, 303) and not REJECTION_HINTS.search(resp["body"][:4000])
        tested.append({
            "method": entry["method"], "action": entry["action"], "field": entry["field"],
            "status": resp["status"], "accepted": accepted,
        })

        if accepted:
            findings.append(Finding(
                title=f"Negative value accepted for numeric field '{entry['field']}'",
                severity="medium",
                confidence="low",
                affected_asset=entry["action"],
                evidence=(
                    f"{entry['method']} to {entry['action']} with {entry['field']}={negative_value} "
                    f"returned HTTP {resp['status']} with no visible validation-rejection message"
                ),
                remediation="Validate numeric business fields server-side (quantity/price/amount must be within an allowed, non-negative range) and verify the field is actually enforced downstream, not just accepted at the HTTP layer.",
                tool="webapp.business_logic",
                references=["CWE-20", "OWASP-A04"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Business logic testing: {len(tested)} numeric field(s) tested, {len(findings)} accepted a negative value without rejection"

    return tool_result(
        "webapp.business_logic", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"forms_with_numeric_fields": len(numeric_fields), "tested": tested},
    )


tool_registry.register("webapp.business_logic", run, metadata={
    "name": "webapp.business_logic",
    "domain": "webapp",
    "status": "completed",
    "description": "Business-logic validation testing: submits a negative value to discovered numeric form fields and checks for acceptance without rejection",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "negative_value": "Negative value to submit for each numeric field (default: '-1')",
    },
})
