#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.subdomain_takeover
Domain: reconnaissance
Real subdomain takeover detector using DNS CNAME resolution + known-vulnerable service signatures.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import re
import socket
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

# Known-vulnerable service takeover fingerprints.
# Each tuple: (service_name, cname_suffix_parts, signature_check)
# cname is matched case-insensitively; if any suffix part appears, we check the signature.
TAKEOVER_SIGNATURES = [
    {
        "service": "AWS S3",
        "cname_patterns": [".amazonaws.com", "s3."],
        "dns_error_patterns": ["NoSuchBucket", "no such bucket", "The specified bucket does not exist"],
    },
    {
        "service": "CloudFront",
        "cname_patterns": [".cloudfront.net"],
        "dns_error_patterns": ["ERROR: The request could not be satisfied", "Bad request", "The request could not be satisfied"],
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": [".github.io", "github.map.fastly.net"],
        "dns_error_patterns": ["There isn't a GitHub Pages site here", "404 - Page not found"],
    },
    {
        "service": "Heroku",
        "cname_patterns": [".herokudns.com", ".herokussl.com", ".herokuapp.com"],
        "dns_error_patterns": ["No such app", "Heroku | No such app"],
    },
    {
        "service": "Azure",
        "cname_patterns": [".azurewebsites.net", ".cloudapp.net", ".azure-api.net", ".trafficmanager.net", "azureedge.net"],
        "dns_error_patterns": ["404 Web Site not found", "This page cannot be displayed", "No such app"],
    },
    {
        "service": "Pantheon",
        "cname_patterns": [".pantheonsite.io", ".pantheon.io"],
        "dns_error_patterns": ["404 error unknown site", "The gods are angry"],
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["domains.tumblr.com"],
        "dns_error_patterns": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    },
    {
        "service": "Shopify",
        "cname_patterns": [".shopify.com", "shops.myshopify.com"],
        "dns_error_patterns": ["Only one step left!", "Sorry, this shop is currently unavailable"],
    },
    {
        "service": "Fastly",
        "cname_patterns": [".fastly.net", ".global.fastly.net", "fastlylb.net"],
        "dns_error_patterns": ["Fastly error: unknown domain", "The page you were looking for doesn't exist"],
    },
    {
        "service": "Bitbucket",
        "cname_patterns": ["bitbucket.io"],
        "dns_error_patterns": ["Repository not found", "This project is empty"],
    },
    {
        "service": "Surge.sh",
        "cname_patterns": [".surge.sh"],
        "dns_error_patterns": ["project not found"],
    },
    {
        "service": "Netlify",
        "cname_patterns": [".netlify.app", ".netlify.com"],
        "dns_error_patterns": ["Not Found - Request ID", "page not found"],
    },
    {
        "service": "ReadTheDocs",
        "cname_patterns": [".readthedocs.io", "readthedocs.io"],
        "dns_error_patterns": ["The page you were looking for doesn't exist"],
    },
    {
        "service": "Zendesk",
        "cname_patterns": [".zendesk.com"],
        "dns_error_patterns": ["Help Center Closed", "Cannot find the page"],
    },
    {
        "service": "Ghost",
        "cname_patterns": [".ghost.io"],
        "dns_error_patterns": ["Domain is not configured"],
    },
]


def _resolve_cname(hostname: str, timeout: float = 5.0) -> str:
    """Return the CNAME target for a hostname, or empty string if none."""
    try:
        answers = socket.gethostbyname_ex(hostname)
    except (socket.gaierror, OSError):
        return ""
    # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
    # We walk the alias list which often contains the canonical CNAME chain.
    for alias in answers[1]:
        if alias.lower() != hostname.lower():
            return alias
    # Fallback: no aliases → single A record, no CNAME
    return ""


def _check_takeover_signature(service_sig: dict, cname: str, hostname: str, timeout: float = 5.0) -> str:
    """Return a signature match string if the CNAME points at an unclaimed service."""
    # Only proceed if the CNAME matches one of the service patterns
    cname_lower = cname.lower()
    if not any(p in cname_lower for p in service_sig["cname_patterns"]):
        return ""

    # The CNAME points at a known cloud service. A takeover is likely if:
    #  1. The CNAME does NOT resolve (NXDOMAIN / no IP) → service account deleted
    #  2. The CNAME resolves but serves an error page indicating unclaimed resource
    try:
        socket.gethostbyname(cname)
    except (socket.gaierror, OSError):
        # CNAME exists in DNS but the target service does not resolve → classic takeover
        return "dangling_cname"

    # CNAME resolves — try HTTP and look for the service error signature
    import urllib.request
    import ssl

    ctx = get_ssl_context(hostname, allow_insecure=True)

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/1.0.0 (Subdomain Takeover Checker)"})
            resp = safe_urlopen(req, timeout=timeout, context=ctx)
            body = resp.read(4096).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = (e.read(4096).decode("utf-8", errors="replace") if e.fp else "") or str(e)
        except Exception:
            continue
        for pattern in service_sig["dns_error_patterns"]:
            if re.search(pattern, body, re.IGNORECASE):
                return f"signature:{pattern}"
    return ""


def run(
    target: str,
    subdomains: str = None,
    timeout: float = 5.0,
    **kwargs: Any,
) -> dict:
    """Detect subdomain takeover vulnerabilities via DNS CNAME + service signatures.

    Parameters
    ----------
    target : str
        Base domain to test (e.g. example.com) or a single hostname.
    subdomains : str, optional
        Comma-separated list of subdomains to test. If omitted, only the target itself is checked.
    timeout : float
        DNS / HTTP timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("reconnaissance.subdomain_takeover", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    checked: list[dict] = []

    # Build the hostname list to test
    hostnames = []
    if subdomains:
        subs = [s.strip().lower() for s in subdomains.split(",") if s.strip()]
        base = target.lower().rstrip(".")
        for sub in subs:
            if "." in sub:
                hostnames.append(sub)
            else:
                hostnames.append(f"{sub}.{base}")
    else:
        hostnames = [target.lower().rstrip(".")]

    for hostname in hostnames:
        cname = _resolve_cname(hostname, timeout)
        if not cname:
            checked.append({"hostname": hostname, "cname": "", "vulnerable": False})
            continue

        for service_sig in TAKEOVER_SIGNATURES:
            match = _check_takeover_signature(service_sig, cname, hostname, timeout)
            if match:
                findings.append(Finding(
                    title=f"Subdomain takeover possible on {hostname}",
                    severity="high",
                    confidence="medium",
                    affected_asset=hostname,
                    evidence=f"CNAME resolves to {cname} ({service_sig['service']}) with takeover indicator: {match}",
                    remediation=(
                        f"Remove the stale DNS record for {hostname} or reclaim the {service_sig['service']} "
                        "resource it points to. Verify no active content is served before deleting."
                    ),
                    tool="reconnaissance.subdomain_takeover",
                    references=["CWE-16", "OWASP-A05"],
                ))
                checked.append({"hostname": hostname, "cname": cname, "service": service_sig["service"], "indicator": match, "vulnerable": True})
                break
        else:
            checked.append({"hostname": hostname, "cname": cname, "vulnerable": False})

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Checked {len(hostnames)} hostname(s): {len(findings)} potential takeover(s) found"
    return tool_result(
        "reconnaissance.subdomain_takeover",
        target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"checked": checked},
    )


tool_registry.register("reconnaissance.subdomain_takeover", run, metadata={
    "name": "reconnaissance.subdomain_takeover",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Detects subdomain takeover via DNS CNAME analysis and known-vulnerable service signatures",
    "parameters": {
        "target": "Base domain or hostname to test",
        "subdomains": "Optional comma-separated subdomain list",
        "timeout": "DNS/HTTP timeout in seconds (default: 5)",
    },
})