#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.tech_fingerprint
Domain: reconnaissance
Technology fingerprinting via HTTP headers, HTML analysis, and response patterns.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import re
import urllib.request
import urllib.parse
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress", r"xmlrpc\.php"],
    "Drupal": [r"drupal", r"sites/all", r"modules/", r"misc/drupal\.js"],
    "Joomla": [r"Joomla!", r"Joomla", r"administrator/", r"components/"],
    "React": [r"react\.(production\.min)?\.js", r"react\.development\.js", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
    "Angular": [r"angular(?:\.min)?\.js", r"angular\.production\.js", r"ng-version", r"__angular__"],
    "Vue": [r"vue(?:\.runtime)?\.js", r"vue\.production\.js", r"__vue__", r"Vue\.version"],
    "Next.js": [r"_next/static", r"_next/dynamic", r"__next", r"next\.js"],
    "Nuxt.js": [r"_nuxt/", r"nuxt\.js", r"__NUXT__"],
    "Svelte": [r"svelte(?:\.dev)?\.js", r"__svelte"],
    "Bootstrap": [r"bootstrap(?:\.min)?\.css", r"bootstrap(?:\.bundle)?\.js"],
    "jQuery": [r"jquery(?:\.min)?\.js", r"\$\.fn\.jquery"],
    "nginx": [r"nginx"],
    "Apache": [r"Apache"],
    "IIS": [r"Microsoft-IIS", r"ASP\.NET"],
}


def _parse_url(target: str) -> str:
    """Normalize URL for fingerprinting."""
    if "://" in target:
        return target.rstrip("/")
    return f"https://{target.rstrip('/')}"


def _fingerprint_html(html: str, headers: dict) -> list[dict]:
    """Detect technologies in HTML content."""
    detected = []
    header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    combined = html.lower() + " " + header_str

    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.append({"technology": tech, "pattern": pattern})
                break

    return detected


def _analyze_cookies(set_cookie: str) -> list[dict]:
    """Analyze Set-Cookie headers for technology clues."""
    clues = []
    if set_cookie:
        if "wordpress" in set_cookie.lower():
            clues.append({"technology": "WordPress", "cookie": "wordpress_"})
        if "php" in set_cookie.lower():
            clues.append({"technology": "PHP", "cookie": "PHPSESSID"})
        if "joomla" in set_cookie.lower():
            clues.append({"technology": "Joomla", "cookie": "joomla"})
        if "laravel" in set_cookie.lower():
            clues.append({"technology": "Laravel", "cookie": "lararavel_session"})
        if "django" in set_cookie.lower():
            clues.append({"technology": "Django", "cookie": "django"})
    return clues


def run(
    target: str,
    analyze_cookies: bool = True,
    timeout: float = 10.0,
    **kwargs: Any,
) -> dict:
    """Perform technology fingerprinting against a target.

    Parameters
    ----------
    target : str
        Hostname or URL to fingerprint.
    analyze_cookies : bool
        Analyze Set-Cookie headers for technology clues.
    timeout : float
        HTTP request timeout in seconds.
    """
    if not target.strip():
        return tool_result("reconnaissance.tech_fingerprint", target, status=STATUS_FAILED, error="Empty target")

    url = _parse_url(target)
    findings: list[Finding] = []
    detected_tech: list[str] = []
    headers_info: dict = {}

    import ssl
    ctx = get_ssl_context(target, allow_insecure=True)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/0.2.0"})
        with safe_urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = dict(resp.headers)
            html = resp.read().decode("utf-8", errors="replace")
            status = resp.status

            findings.append(Finding(
                title=f"HTTP response from {url}",
                severity="info",
                confidence="certain",
                affected_asset=url,
                evidence=f"Status: {status}, Content-Length: {len(html)}",
                remediation="No action needed - informational.",
                tool="reconnaissance.tech_fingerprint",
            ))

            if headers.get("Server"):
                detected_tech.append(headers["Server"])
                findings.append(Finding(
                    title="Server header detected",
                    severity="info",
                    confidence="certain",
                    affected_asset=url,
                    evidence=f"Server: {headers['Server']}",
                    remediation="Review server header disclosure.",
                    tool="reconnaissance.tech_fingerprint",
                    references=["CWE-200"],
                ))

            if headers.get("X-Powered-By"):
                detected_tech.append(headers["X-Powered-By"])
                findings.append(Finding(
                    title="X-Powered-By header detected",
                    severity="low",
                    confidence="certain",
                    affected_asset=url,
                    evidence=f"X-Powered-By: {headers['X-Powered-By']}",
                    remediation="Remove X-Powered-By header to reduce information disclosure.",
                    tool="reconnaissance.tech_fingerprint",
                    references=["CWE-200"],
                ))

            html_tech = _fingerprint_html(html, headers)
            for tech_info in html_tech:
                if tech_info["technology"] not in detected_tech:
                    detected_tech.append(tech_info["technology"])
                    findings.append(Finding(
                        title=f"Technology detected: {tech_info['technology']}",
                        severity="info",
                        confidence="high",
                        affected_asset=url,
                        evidence=f"Detected via pattern: {tech_info['pattern'][:50]}",
                        remediation="Verify technology detection is accurate.",
                        tool="reconnaissance.tech_fingerprint",
                        references=["CWE-200"],
                    ))

            if analyze_cookies and headers.get("Set-Cookie"):
                cookie_clues = _analyze_cookies(headers["Set-Cookie"])
                for clue in cookie_clues:
                    if clue["technology"] not in detected_tech:
                        detected_tech.append(clue["technology"])
                        findings.append(Finding(
                            title=f"Technology detected via cookie: {clue['technology']}",
                            severity="info",
                            confidence="medium",
                            affected_asset=url,
                            evidence=f"Cookie pattern: {clue['cookie']}",
                            remediation="Verify technology detection is accurate.",
                            tool="reconnaissance.tech_fingerprint",
                            references=["CWE-200"],
                        ))

    except urllib.error.HTTPError as e:
        findings.append(Finding(
            title=f"HTTP error during fingerprinting",
            severity="low",
            confidence="certain",
            affected_asset=url,
            evidence=f"HTTP {e.code}: {e.reason}",
            remediation="Verify target is accessible.",
            tool="reconnaissance.tech_fingerprint",
        ))
    except urllib.error.URLError as e:
        findings.append(Finding(
            title=f"URL error during fingerprinting",
            severity="low",
            confidence="certain",
            affected_asset=url,
            evidence=str(e.reason),
            remediation="Verify target is accessible.",
            tool="reconnaissance.tech_fingerprint",
        ))
    except Exception as e:
        findings.append(Finding(
            title="Fingerprinting error",
            severity="low",
            confidence="medium",
            affected_asset=url,
            evidence=str(e)[:100],
            remediation="Verify target is responding correctly.",
            tool="reconnaissance.tech_fingerprint",
        ))

    if detected_tech:
        return tool_result(
            "reconnaissance.tech_fingerprint", target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Detected {len(detected_tech)} technologies: {', '.join(set(detected_tech))}",
            metadata={"technologies": list(set(detected_tech))},
        )

    return tool_result(
        "reconnaissance.tech_fingerprint", target,
        status=STATUS_NO_FINDINGS,
        summary=f"No technology fingerprints detected for {url}",
        metadata={"technologies": []},
    )


tool_registry.register("reconnaissance.tech_fingerprint", run, metadata={
    "name": "reconnaissance.tech_fingerprint",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Technology fingerprinting via HTTP headers and HTML analysis",
    "parameters": {
        "target": "Target hostname or URL",
        "analyze_cookies": "Analyze Set-Cookie headers (default: True)",
        "timeout": "HTTP request timeout in seconds (default: 10s)",
    },
})