#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.crawler
Domain: webapp
Website crawler with header analysis, link extraction, and form discovery.
"""
from __future__ import annotations

import re
import socket
import ssl
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


def _normalize_url(target: str, original_url: str) -> str:
    """Normalize a URL based on the original URL context."""
    if "://" in target:
        return target
    if target.startswith("//"):
        return f"{urllib.parse.urlparse(original_url).scheme}:{target}"
    if target.startswith("/"):
        base = "/".join(urllib.parse.urlparse(original_url).scheme.split("/")[0:2])
        base = original_url.rsplit("/", 1)[0] if "/" in original_url else original_url
        return f"{base}{target}"
    return f"{original_url.rstrip('/')}/{target}"


def _make_soup(html: str) -> Any:
    """Parse HTML with BeautifulSoup if available, else return None."""
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html, "html.parser")
    except ImportError:
        return None


def _extract_links(soup: Any, base_url: str, html: str = "") -> list[str]:
    """Extract all links from parsed HTML."""
    links = []
    if soup:
        for link in soup.find_all("a", href=True):
            url = _normalize_url(link["href"], base_url)
            links.append(url)
        for script in soup.find_all("script", src=True):
            url = _normalize_url(script["src"], base_url)
            links.append(url)
        for img in soup.find_all("img", src=True):
            url = _normalize_url(img["src"], base_url)
            links.append(url)
    else:
        links.extend(re.findall(r'href=["\']([^"\']+)["\']', html))
        links.extend(re.findall(r'src=["\']([^"\']+)["\']', html))
    return links


def _extract_forms(soup: Any, base_url: str) -> list[dict]:
    """Extract forms from parsed HTML."""
    forms = []
    if soup:
        for form in soup.find_all("form"):
            form_data = {
                "action": _normalize_url(form.get("action", ""), base_url),
                "method": (form.get("method") or "GET").upper(),
                "inputs": [],
            }
            for inp in form.find_all("input"):
                form_data["inputs"].append({
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            forms.append(form_data)
    return forms


def _analyze_headers(headers: dict) -> list[Finding]:
    """Analyze HTTP headers for security issues."""
    findings = []
    header_lower = {k.lower(): v for k, v in headers.items()}

    if header_lower.get("server"):
        findings.append(Finding(
            title="Server header exposes technology",
            severity="low",
            confidence="certain",
            affected_asset=headers.get("server", ""),
            evidence=f"Server: {header_lower['server']}",
            remediation="Remove or obfuscate server version in HTTP response.",
            tool="webapp.crawler",
            references=["CWE-200"],
        ))

    if header_lower.get("x-powered-by"):
        findings.append(Finding(
            title="X-Powered-By header exposes technology",
            severity="low",
            confidence="certain",
            affected_asset=headers.get("x-powered-by", ""),
            evidence=f"X-Powered-By: {header_lower['x-powered-by']}",
            remediation="Remove X-Powered-By header to reduce information disclosure.",
            tool="webapp.crawler",
            references=["CWE-200"],
        ))

    # Security header checks
    security_headers = {
        "strict-transport-security": "HSTS - Prevents downgrade attacks",
        "content-security-policy": "CSP - Prevents XSS and injection",
        "x-content-type-options": "X-Content-Type-Options - Prevents MIME sniffing",
        "x-frame-options": "X-Frame-Options - Prevents clickjacking",
        "x-xss-protection": "X-XSS-Protection - Legacy XSS filter",
        "referrer-policy": "Referrer-Policy - Controls referrer leakage",
    }

    for header, purpose in security_headers.items():
        if header not in header_lower:
            findings.append(Finding(
                title=f"Missing security header: {header}",
                severity="medium",
                confidence="high",
                affected_asset=header,
                evidence=f"Header '{header}' not present - {purpose}",
                remediation=f"Add {header} header to improve security posture.",
                tool="webapp.crawler",
                references=["CWE-693", "CWE-1021"],
            ))

    return findings


def _check_robots_txt(base_url: str) -> Optional[str]:
    """Check for robots.txt file."""
    try:
        scheme = urllib.parse.urlparse(base_url).scheme
        netloc = urllib.parse.urlparse(base_url).netloc
        url = f"{scheme}://{netloc}/robots.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/0.2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8", errors="replace")[:5000]
    except Exception:
        pass
    return None


def run(
    target: str,
    max_pages: int = 10,
    follow_links: bool = True,
    analyze_headers: bool = True,
    check_robots: bool = True,
    timeout: float = 10.0,
    **kwargs: Any,
) -> dict:
    """Crawl a website and extract information.

    Parameters
    ----------
    target : str
        Starting URL or hostname for crawling.
    max_pages : int
        Maximum number of pages to visit.
    follow_links : bool
        Follow discovered links to crawl recursively.
    analyze_headers : bool
        Analyze HTTP headers for security issues.
    check_robots : bool
        Check for robots.txt file.
    timeout : float
        HTTP request timeout in seconds.
    """
    if not target.strip():
        return tool_result("webapp.crawler", target, status=STATUS_FAILED, error="Empty target")

    start_url = target if "://" in target else f"https://{target}"
    parsed = urllib.parse.urlparse(start_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []
    visited: set[str] = set()
    to_visit: list[str] = [start_url]
    crawled_count = 0

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    while to_visit and crawled_count < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        crawled_count += 1

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/0.2.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                html = resp.read().decode("utf-8", errors="replace")
                headers = dict(resp.headers)

                if analyze_headers:
                    header_findings = _analyze_headers(headers)
                    findings.extend(header_findings)

                soup = _make_soup(html)
                if soup:
                    forms = _extract_forms(soup, url)
                    for form in forms:
                        findings.append(Finding(
                            title=f"Form discovered at {url}",
                            severity="info",
                            confidence="certain",
                            affected_asset=url,
                            evidence=f"Method: {form['method']} Action: {form['action']} Inputs: {len(form['inputs'])}",
                            remediation="Review form for CSRF protection and input validation.",
                            tool="webapp.crawler",
                            references=["CWE-352", "CWE-20"],
                        ))

                if follow_links:
                    links = _extract_links(soup, url, html)
                    for link in links[:20]:
                        if link not in visited and "://" in link:
                            try:
                                link_parsed = urllib.parse.urlparse(link)
                                if link_parsed.netloc == parsed.netloc:
                                    to_visit.append(link)
                            except Exception:
                                pass

        except urllib.error.HTTPError as e:
            findings.append(Finding(
                title=f"HTTP error on {url}",
                severity="info",
                confidence="certain",
                affected_asset=url,
                evidence=f"HTTP {e.code}: {e.reason}",
                remediation="Verify URL is accessible and authorized.",
                tool="webapp.crawler",
            ))
        except urllib.error.URLError as e:
            findings.append(Finding(
                title=f"URL error on {url}",
                severity="low",
                confidence="medium",
                affected_asset=url,
                evidence=str(e.reason),
                remediation="Check if host is reachable and URL is valid.",
                tool="webapp.crawler",
            ))
        except Exception as e:
            findings.append(Finding(
                title=f"Crawl error on {url}",
                severity="low",
                confidence="medium",
                affected_asset=url,
                evidence=str(e)[:100],
                remediation="Verify target is responding and accessible.",
                tool="webapp.crawler",
            ))

    if check_robots:
        robots = _check_robots_txt(base_url)
        if robots:
            findings.append(Finding(
                title=f"robots.txt found for {base_url}",
                severity="info",
                confidence="certain",
                affected_asset=base_url,
                evidence=f"robots.txt: {robots[:500]}...",
                remediation="Review robots.txt for sensitive paths.",
                tool="webapp.crawler",
                references=["CWE-538"],
            ))

    return tool_result(
        "webapp.crawler", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Crawled {crawled_count} page{'s' if crawled_count > 1 else ''} under {base_url}",
        metadata={
            "base_url": base_url,
            "pages_crawled": crawled_count,
            "findings_count": len(findings),
        },
    )


tool_registry.register("webapp.crawler", run, metadata={
    "name": "webapp.crawler",
    "domain": "webapp",
    "status": "completed",
    "description": "Website crawler with header analysis, link extraction, and form discovery",
    "parameters": {
        "target": "Starting URL or hostname for crawling",
        "max_pages": "Maximum pages to visit (default: 10)",
        "follow_links": "Follow discovered links to crawl recursively (default: True)",
        "analyze_headers": "Analyze HTTP headers for security issues (default: True)",
        "check_robots": "Check for robots.txt file (default: True)",
        "timeout": "HTTP request timeout in seconds (default: 10s)",
    },
})