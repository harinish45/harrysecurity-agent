#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.waf_detect
Domain: reconnaissance
Real WAF detection via response header analysis + payload testing.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen
import urllib.request
import urllib.parse
import ssl
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare-nginx", "__cfduid"],
    "Akamai": ["akamai", "akamaighost"],
    "AWS WAF": ["awswaf", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 Big-IP": ["bigip", "f5"],
    "Imperva": ["incapsula", "imperva"]
}

PROBE_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "../../../etc/passwd"
]

def run(target: str, **kwargs: Any) -> dict:
    """Detect Web Application Firewall (WAF) presence via headers and probe responses."""
    findings = []
    waf_detected = []
    
    try:
        url = target if "://" in target else f"http://{target}"
        ctx = get_ssl_context(target, allow_insecure=True)
        
        # 1. Header analysis
        req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/0.2.0 (WAF Detector)"})
        resp = safe_urlopen(req, timeout=10, context=ctx)
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            if any(sig in str(headers_lower) for sig in signatures):
                waf_detected.append(waf_name)
                findings.append(Finding(
                    title=f"Web Application Firewall Detected: {waf_name}",
                    severity="low",
                    confidence="high",
                    affected_asset=url,
                    evidence=f"WAF signatures found in response headers: {', '.join(signatures)}",
                    remediation="Ensure WAF rules are regularly updated and tuned to minimize false positives.",
                    tool="reconnaissance.waf_detect",
                    references=["OWASP-WAF"]
                ))
                
        # 2. Payload testing
        for payload in PROBE_PAYLOADS:
            test_url = f"{url}?q={urllib.parse.quote(payload)}"
            try:
                req_probe = urllib.request.Request(test_url, headers={"User-Agent": "NEXUS-STRIKE/0.2.0"})
                resp_probe = safe_urlopen(req_probe, timeout=10, context=ctx)
                if resp_probe.status in [403, 406, 419, 503]:
                    if not waf_detected:
                        waf_detected.append("Unknown WAF")
                        findings.append(Finding(
                            title="Potential WAF Blocking Malicious Payloads",
                            severity="low",
                            confidence="medium",
                            affected_asset=url,
                            evidence=f"Request with payload '{payload[:20]}...' was blocked with status {resp_probe.status}.",
                            remediation="Verify WAF configuration and review blocked requests for false positives.",
                            tool="reconnaissance.waf_detect",
                            references=["OWASP-WAF"]
                        ))
                    break
            except urllib.error.HTTPError as e:
                if e.code in [403, 406, 419, 503]:
                    if not waf_detected:
                        waf_detected.append("Unknown WAF")
                        findings.append(Finding(
                            title="Potential WAF Blocking Malicious Payloads",
                            severity="low",
                            confidence="medium",
                            affected_asset=url,
                            evidence=f"Request with payload '{payload[:20]}...' was blocked with status {e.code}.",
                            remediation="Verify WAF configuration and review blocked requests for false positives.",
                            tool="reconnaissance.waf_detect",
                            references=["OWASP-WAF"]
                        ))
                    break
            except Exception:
                pass
                
        if not waf_detected:
            findings.append(Finding(
                title="No WAF Detected",
                severity="low",
                confidence="medium",
                affected_asset=url,
                evidence="No known WAF signatures or blocking behaviors were observed.",
                remediation="Consider deploying a WAF to protect against common web vulnerabilities.",
                tool="reconnaissance.waf_detect",
                references=["OWASP-WAF"]
            ))
            
        summary = f"WAF detection completed. Identified: {', '.join(waf_detected) if waf_detected else 'None'}"
        status = STATUS_COMPLETED
        
    except Exception as e:
        return tool_result("reconnaissance.waf_detect", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "reconnaissance.waf_detect", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"waf_detected": waf_detected}
    )

tool_registry.register("reconnaissance.waf_detect", run, metadata={
    "name": "reconnaissance.waf_detect",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Detects Web Application Firewalls via response header analysis and probe payloads",
    "parameters": {"target": "Target URL or hostname"},
})