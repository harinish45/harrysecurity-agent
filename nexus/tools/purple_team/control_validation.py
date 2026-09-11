#!/usr/bin/env python3
"""
NEXUS-STRIKE — purple_team.control_validation
Domain: purple_team
Real validation that specific security controls are observably present on
a target — a genuine HTTP(S) check of security-relevant response headers
(CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) via
safe_urlopen, not a simulation. Each header is a real, independently
verifiable control; presence/absence is reported exactly as observed.
"""
from __future__ import annotations

import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.red_team._ttp_common import resolve_target

# header_name -> (severity_if_missing, mitre_technique_id_or_None, mitre_name, description)
_SECURITY_HEADERS: dict[str, tuple[str, str | None, str, str]] = {
    "Content-Security-Policy": (
        "medium", "T1189", "Drive-by Compromise",
        "Restricts script/resource origins, mitigating XSS-driven drive-by compromise and data injection.",
    ),
    "Strict-Transport-Security": (
        "medium", "T1557", "Adversary-in-the-Middle",
        "Forces HTTPS on future visits, mitigating TLS-downgrade / SSL-stripping AiTM attacks.",
    ),
    "X-Frame-Options": (
        "low", None, "Clickjacking protection",
        "Prevents the page from being framed by a third-party site (UI-redress/clickjacking).",
    ),
    "X-Content-Type-Options": (
        "low", None, "MIME-sniffing protection",
        "Prevents the browser from MIME-sniffing a response away from its declared content type.",
    ),
    "Referrer-Policy": (
        "low", None, "Referrer leakage protection",
        "Limits how much of the URL is leaked to third parties via the Referer header.",
    ),
}


def run(target: str, timeout: float = 5.0, **kwargs: Any) -> dict:
    """Real HTTP(S) check for the presence of key security-control response headers.

    Parameters
    ----------
    target : str
        Target domain, IP, or URL.
    timeout : float
        HTTP request timeout in seconds.
    """
    ip, dns_note = resolve_target(target)
    if ip is None:
        return tool_result("purple_team.control_validation", target, status=STATUS_FAILED, error=dns_note)

    urls_to_try = [target] if "://" in target else [f"https://{target}/", f"http://{target}/"]

    resp = None
    scheme_used = None
    last_error = ""
    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = safe_urlopen(req, timeout=timeout)
            scheme_used = url
            break
        except Exception as exc:
            last_error = str(exc)[:120]
            continue

    if resp is None:
        return tool_result(
            "purple_team.control_validation", target,
            status=STATUS_FAILED,
            error=f"Could not reach {target} over HTTP(S): {last_error}",
        )

    headers = resp.headers
    findings: list[Finding] = []
    present: list[str] = []
    missing: list[str] = []

    for header_name, (missing_severity, tid, mitre_name, description) in _SECURITY_HEADERS.items():
        value = headers.get(header_name)
        if value:
            present.append(header_name)
            findings.append(Finding(
                title=f"Security control present: {header_name}",
                severity="info",
                confidence="certain",
                affected_asset=target,
                evidence=f"Real HTTP response from {scheme_used} includes {header_name}: {value[:200]}",
                remediation="No action — control observed as present.",
                tool="purple_team.control_validation",
                references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"] if tid else [],
            ))
        else:
            missing.append(header_name)
            findings.append(Finding(
                title=f"Security control missing: {header_name}",
                severity=missing_severity,
                confidence="certain",
                affected_asset=target,
                evidence=f"Real HTTP response from {scheme_used} does NOT include a {header_name} header.",
                remediation=f"Add the {header_name} response header. {description}",
                tool="purple_team.control_validation",
                references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"] if tid else ["CWE-693"],
            ))

    return tool_result(
        "purple_team.control_validation", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=(
            f"Control validation complete against {scheme_used}: {len(present)}/{len(_SECURITY_HEADERS)} "
            f"security headers present. Missing: {', '.join(missing) if missing else 'none'}."
        ),
        metadata={
            "dns_resolved_ip": ip,
            "url_checked": scheme_used,
            "http_status": resp.status,
            "headers_present": present,
            "headers_missing": missing,
        },
    )


tool_registry.register("purple_team.control_validation", run, metadata={
    "name": "purple_team.control_validation",
    "domain": "purple_team",
    "status": "completed",
    "description": (
        "Real HTTP(S) check that specific security controls (CSP, HSTS, X-Frame-Options, "
        "X-Content-Type-Options, Referrer-Policy) are observably present on the target's "
        "response headers via safe_urlopen — not a simulation."
    ),
    "parameters": {
        "target": "Target domain, IP, or URL",
        "timeout": "HTTP request timeout in seconds (default: 5)",
    },
})
