#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.param_discovery
Domain: webapp
Hidden/undocumented HTTP parameter discovery.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no parameter probing at all).
Now: a real baseline GET of the target root, then a real GET per entry in
a bundled common-parameter wordlist, comparing each probed response's
status code and body size against the baseline to flag parameters that
measurably change application behavior (a strong signal of an
undocumented/hidden parameter the application actually reads).
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Parameter Discovery)"

COMMON_PARAMS = [
    "id", "page", "file", "user", "username", "debug", "admin", "test",
    "redirect", "redirect_url", "return", "returnurl", "next", "url",
    "callback", "format", "lang", "sort", "order", "limit", "offset",
    "q", "search", "query", "filter", "token", "key", "api_key", "apikey",
    "action", "cmd", "path", "view", "template", "mode", "type", "src",
    "dest", "target", "ref", "referer", "session", "sid", "access_token",
    "auth", "role", "level", "verbose", "trace", "show", "hidden",
    "internal", "preview", "beta", "version", "v", "output", "data",
]


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


def run(
    target: str,
    wordlist: list[str] | None = None,
    probe_value: str = "nexus_probe_1",
    max_params: int = 100,
    timeout: int = 10,
    **kwargs: Any,
) -> dict:
    """Discover hidden/undocumented parameters that change application behavior.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    wordlist : list[str], optional
        Custom parameter wordlist. Defaults to a bundled common-parameter list.
    probe_value : str
        Value to send for each candidate parameter.
    max_params : int
        Maximum parameters to probe.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.param_discovery", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    discovered: list[dict] = []

    baseline = _http_request(base_url, timeout)
    if baseline["status"] == 0:
        return tool_result("webapp.param_discovery", target, status=STATUS_FAILED, error=baseline.get("error") or "Connection failed")

    params = (wordlist or COMMON_PARAMS)[:max_params]
    parsed = urllib.parse.urlparse(base_url)

    for param in params:
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = probe_value
        test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
        resp = _http_request(test_url, timeout)
        if resp["status"] == 0:
            continue

        status_changed = resp["status"] != baseline["status"]
        size_diff = abs(resp["size"] - baseline["size"])
        size_ratio = size_diff / max(baseline["size"], 1)
        size_changed = size_ratio > 0.05 and size_diff > 25

        if status_changed or size_changed:
            discovered.append({
                "param": param,
                "baseline_status": baseline["status"],
                "probe_status": resp["status"],
                "baseline_size": baseline["size"],
                "probe_size": resp["size"],
                "size_ratio_diff": round(size_ratio, 3),
            })
            findings.append(Finding(
                title=f"Hidden parameter '{param}' changes application behavior",
                severity="low",
                confidence="medium",
                affected_asset=test_url,
                evidence=(
                    f"Baseline: HTTP {baseline['status']} / {baseline['size']}B; "
                    f"with '{param}={probe_value}': HTTP {resp['status']} / {resp['size']}B"
                ),
                remediation="Review whether this parameter exposes debug output, alternate behavior, or bypasses controls; document or remove it.",
                tool="webapp.param_discovery",
                references=["CWE-1059"],
            ))

    status = STATUS_COMPLETED if discovered else STATUS_NO_FINDINGS
    summary = f"Parameter discovery: {len(params)} candidate(s) probed, {len(discovered)} behavior-changing parameter(s) found"

    return tool_result(
        "webapp.param_discovery", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"probed": len(params), "discovered": discovered},
    )


tool_registry.register("webapp.param_discovery", run, metadata={
    "name": "webapp.param_discovery",
    "domain": "webapp",
    "status": "completed",
    "description": "Hidden HTTP parameter discovery via wordlist probing and baseline response comparison",
    "parameters": {
        "target": "Target URL or hostname to test",
        "wordlist": "Custom parameter wordlist (default: bundled common-parameter list)",
        "probe_value": "Value sent for each candidate parameter (default: 'nexus_probe_1')",
        "max_params": "Maximum parameters to probe (default: 100)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})
