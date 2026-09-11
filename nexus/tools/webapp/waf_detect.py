#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.waf_detect
Domain: webapp
Web Application Firewall (WAF) fingerprinting.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no WAF-signature matching at all).
Now: a real baseline GET plus a real malicious-shaped probe GET (a
harmless-but-signature-triggering payload in the query string), matching
real response headers/cookies against a fingerprint table of known WAF/CDN
security products, and comparing the baseline vs. probe response status to
detect whether the malicious-shaped request was blocked.
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (WAF Detector)"

# (header/cookie name, substring to match in its value, product name) —
# checked against both headers and Set-Cookie values.
WAF_SIGNATURES = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("cf-cache-status", "", "Cloudflare"),
    ("set-cookie", "__cfduid", "Cloudflare"),
    ("set-cookie", "__cf_bm", "Cloudflare Bot Management"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "sucuri", "Sucuri"),
    ("set-cookie", "incap_ses", "Imperva Incapsula"),
    ("set-cookie", "visid_incap", "Imperva Incapsula"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("x-cdn", "imperva", "Imperva"),
    ("server", "awselb", "AWS Elastic Load Balancer"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-amzn-requestid", "", "AWS API Gateway/WAF"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    ("x-distil-cs", "", "Distil Networks"),
    ("server", "distil", "Distil Networks"),
    ("x-denied-reason", "", "Generic WAF (denial header)"),
    ("x-waf-event-info", "", "Generic WAF"),
    ("server", "barracuda", "Barracuda WAF"),
    ("set-cookie", "barra_counter_session", "Barracuda WAF"),
    ("x-fw-hash", "", "F5 BIG-IP ASM"),
    ("set-cookie", "ts01", "F5 BIG-IP"),
    ("set-cookie", "bigipserver", "F5 BIG-IP"),
    ("server", "citrix", "Citrix NetScaler"),
    ("set-cookie", "citrix_ns_id", "Citrix NetScaler"),
    ("set-cookie", "ns_af", "Citrix NetScaler AppFirewall"),
    ("x-protected-by", "sqreen", "Sqreen"),
    ("server", "wts", "AppTrana WAF"),
    ("x-fireeye-blocked", "", "FireEye"),
    ("server", "safe3waf", "Safe3 WAF"),
]

MALICIOUS_PROBE_QUERY = "id=1' UNION SELECT NULL-- -&x=<script>alert(1)</script>&y=../../../../etc/passwd"

BLOCK_STATUS_CODES = {403, 406, 419, 429, 501, 999}


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET and return status/headers/cookies."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(8192).decode("utf-8", errors="replace")
        cookies = resp.headers.get_all("Set-Cookie") or []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return {"status": resp.status, "headers": headers, "cookies": cookies, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(8192).decode("utf-8", errors="replace") if e.fp else ""
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return {"status": e.code, "headers": headers, "cookies": cookies or [], "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "cookies": [], "body": "", "error": str(e)[:100]}


def _match_signatures(resp: dict) -> list[str]:
    matched = []
    for header_name, needle, product in WAF_SIGNATURES:
        value = resp["headers"].get(header_name, "")
        haystacks = [value] + (resp["cookies"] if header_name == "set-cookie" else [])
        for haystack in haystacks:
            if not haystack:
                continue
            if not needle or needle.lower() in haystack.lower():
                if product not in matched:
                    matched.append(product)
                break
    return matched


def run(target: str, timeout: int = 10, **kwargs: Any) -> dict:
    """Fingerprint a WAF/CDN security product in front of target.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.waf_detect", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []

    baseline = _http_request(base_url, timeout)
    if baseline["status"] == 0:
        return tool_result("webapp.waf_detect", target, status=STATUS_FAILED, error=baseline.get("error") or "Connection failed")

    parsed = urllib.parse.urlparse(base_url)
    probe_url = urllib.parse.urlunparse(parsed._replace(query=MALICIOUS_PROBE_QUERY))
    probe = _http_request(probe_url, timeout)

    products = _match_signatures(baseline)
    if not products:
        products = _match_signatures(probe)

    blocked = probe["status"] in BLOCK_STATUS_CODES and probe["status"] != baseline["status"]

    if products:
        findings.append(Finding(
            title=f"WAF/CDN security product identified: {', '.join(products)}",
            severity="info",
            confidence="high",
            affected_asset=base_url,
            evidence=f"Fingerprint match in response headers/cookies for: {', '.join(products)}",
            remediation="Informational — confirms a WAF/CDN is in front of the application. Verify its ruleset is tuned for this application.",
            tool="webapp.waf_detect",
            references=[],
        ))

    if blocked:
        findings.append(Finding(
            title="Malicious-shaped request was blocked",
            severity="info",
            confidence="high",
            affected_asset=base_url,
            evidence=f"Baseline HTTP {baseline['status']}; malicious-shaped probe (SQLi/XSS/traversal payload in query string) returned HTTP {probe['status']}",
            remediation="Informational — indicates active request filtering is in place.",
            tool="webapp.waf_detect",
            references=[],
        ))
    elif not products:
        findings.append(Finding(
            title="No WAF/CDN detected",
            severity="low",
            confidence="medium",
            affected_asset=base_url,
            evidence=(
                f"No known WAF/CDN fingerprint matched, and a malicious-shaped probe "
                f"(HTTP {probe['status']}) was not treated differently from baseline (HTTP {baseline['status']})"
            ),
            remediation="Consider deploying a WAF as a defense-in-depth layer in front of the application.",
            tool="webapp.waf_detect",
            references=["CWE-693"],
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = (
        f"WAF detection: {'product(s) identified: ' + ', '.join(products) if products else 'no fingerprint match'}; "
        f"malicious probe {'blocked' if blocked else 'not blocked'} (baseline {baseline['status']} vs probe {probe['status']})"
    )

    return tool_result(
        "webapp.waf_detect", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={
            "products_detected": products,
            "baseline_status": baseline["status"],
            "probe_status": probe["status"],
            "probe_blocked": blocked,
        },
    )


tool_registry.register("webapp.waf_detect", run, metadata={
    "name": "webapp.waf_detect",
    "domain": "webapp",
    "status": "completed",
    "description": "WAF/CDN fingerprinting via header/cookie signature matching plus a malicious-shaped probe vs. baseline comparison",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})
