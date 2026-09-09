#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.idor
Domain: webapp
Insecure Direct Object Reference (IDOR) detection via adjacent-ID substitution.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no ID enumeration at all).
Now: a real preliminary crawl of the target to discover numeric path
segments (e.g. ``/user/1042``) and ``id=``-style query parameters, then
real GETs substituting adjacent/sequential numeric IDs, comparing response
status code and body size against the original to flag object references
that are (a) not access-controlled — an adjacent, presumably-not-ours ID
still returns 200 with substantially similar content — and (b) trivially
enumerable, sequential integers rather than opaque identifiers.
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (IDOR Detector)"

NUMERIC_PATH_SEGMENT = re.compile(r"/(\d{1,10})(?=/|$|\?)")
LINK_PATTERN = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET and return status/body/size."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "size": len(body), "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "body": body, "size": len(body), "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "size": 0, "error": str(e)[:100]}


def _discover_numeric_targets(base_url: str, html: str) -> list[dict]:
    """Find numeric path segments and id= query params reachable from base_url."""
    candidates: list[dict] = []

    for m in NUMERIC_PATH_SEGMENT.finditer(urllib.parse.urlparse(base_url).path):
        candidates.append({"kind": "path", "url": base_url, "value": int(m.group(1)), "span": m.span()})

    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.parse_qs(parsed.query)
    for key, values in query.items():
        if key.lower() in ("id", "uid", "user_id", "account", "order", "invoice") and values and values[0].isdigit():
            candidates.append({"kind": "query", "url": base_url, "param": key, "value": int(values[0])})

    for link in LINK_PATTERN.finditer(html):
        href = link.group(1)
        full = urllib.parse.urljoin(base_url, href)
        linked_parsed = urllib.parse.urlparse(full)
        path_match = NUMERIC_PATH_SEGMENT.search(linked_parsed.path)
        if path_match:
            candidates.append({"kind": "path", "url": full, "value": int(path_match.group(1)), "span": path_match.span()})
            continue
        linked_query = urllib.parse.parse_qs(linked_parsed.query)
        for key, values in linked_query.items():
            if key.lower() in ("id", "uid", "user_id", "account", "order", "invoice") and values and values[0].isdigit():
                candidates.append({"kind": "query", "url": full, "param": key, "value": int(values[0])})

    return candidates


def _substitute(candidate: dict, new_value: int) -> str:
    if candidate["kind"] == "path":
        parsed = urllib.parse.urlparse(candidate["url"])
        start, end = candidate["span"]
        new_path = parsed.path[:start] + f"/{new_value}" + parsed.path[end:]
        return urllib.parse.urlunparse(parsed._replace(path=new_path))
    parsed = urllib.parse.urlparse(candidate["url"])
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[candidate["param"]] = str(new_value)
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


def run(target: str, timeout: int = 10, max_candidates: int = 5, **kwargs: Any) -> dict:
    """Discover and test numeric object references for IDOR.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    max_candidates : int
        Maximum numeric ID candidates to test.
    """
    if not target or not target.strip():
        return tool_result("webapp.idor", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    vulns: list[dict] = []

    baseline = _http_request(base_url, timeout)
    if baseline["status"] == 0:
        return tool_result("webapp.idor", target, status=STATUS_FAILED, error=baseline.get("error") or "Connection failed")

    candidates = _discover_numeric_targets(base_url, baseline["body"])
    if not candidates:
        return tool_result(
            "webapp.idor", target,
            status=STATUS_NO_FINDINGS,
            summary="No numeric path segment or id= parameter discovered via preliminary crawl — nothing to substitute for IDOR testing.",
            metadata={"candidates_found": 0},
        )

    tested = 0
    for candidate in candidates[:max_candidates]:
        original_value = candidate["value"]
        original_url = _substitute(candidate, original_value)
        original_resp = _http_request(original_url, timeout)
        if original_resp["status"] != 200:
            continue

        for delta in (1, -1, 2):
            adjacent_value = original_value + delta
            if adjacent_value < 0:
                continue
            adjacent_url = _substitute(candidate, adjacent_value)
            adjacent_resp = _http_request(adjacent_url, timeout)
            tested += 1

            if adjacent_resp["status"] == 200:
                size_diff = abs(adjacent_resp["size"] - original_resp["size"])
                size_ratio = size_diff / max(original_resp["size"], 1)
                if size_ratio < 0.3:
                    vulns.append({
                        "kind": candidate["kind"],
                        "original_id": original_value,
                        "adjacent_id": adjacent_value,
                        "original_url": original_url,
                        "adjacent_url": adjacent_url,
                        "size_ratio_diff": round(size_ratio, 3),
                    })
                    findings.append(Finding(
                        title=f"Potential IDOR: adjacent numeric ID {adjacent_value} returns similar content to {original_value}",
                        severity="high",
                        confidence="medium",
                        affected_asset=adjacent_url,
                        evidence=(
                            f"ID {original_value} -> HTTP {original_resp['status']} ({original_resp['size']}B); "
                            f"adjacent ID {adjacent_value} -> HTTP {adjacent_resp['status']} ({adjacent_resp['size']}B), "
                            f"size difference {size_ratio:.0%} — object reference may lack access-control checks."
                        ),
                        remediation="Verify server-side that the authenticated user is authorized to access the referenced object, independent of guessability of the identifier.",
                        tool="webapp.idor",
                        references=["CWE-639", "OWASP-A01"],
                    ))
                    break

    status = STATUS_COMPLETED if vulns else STATUS_NO_FINDINGS
    summary = f"IDOR testing: {len(candidates)} numeric reference(s) discovered, {tested} adjacent-ID probe(s) sent, {len(vulns)} potential IDOR(s)"

    return tool_result(
        "webapp.idor", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"candidates_found": len(candidates), "probes_sent": tested, "vulnerabilities": vulns},
    )


tool_registry.register("webapp.idor", run, metadata={
    "name": "webapp.idor",
    "domain": "webapp",
    "status": "completed",
    "description": "IDOR detection via preliminary crawl for numeric object references, then adjacent-ID substitution and response comparison",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "max_candidates": "Maximum numeric ID candidates to test (default: 5)",
    },
})
