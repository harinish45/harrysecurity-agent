#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.deserialization
Domain: webapp
Real deserialization detection: sends Java/PHP/Python serialized objects, detects gadget chain errors.
"""
from __future__ import annotations
import urllib.request
import ssl
import base64
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

# Common deserialization payloads (proof-of-concept, non-destructive)
DESERIAL_PAYLOADS = {
    "java": base64.b64encode(b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01t\x00\x04testt\x00\x04testx").decode('utf-8'),
    "php": base64.b64encode(b"O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}").decode('utf-8'),
    "python_pickle": base64.b64encode(b"\x80\x04\x95\x1b\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04exec\x94\x93\x94\x8c\x08print(1)\x94\x85\x94R\x94.").decode('utf-8')
}

def run(target: str, **kwargs: Any) -> dict:
    """Perform insecure deserialization testing."""
    findings = []
    vuln_indicators = []
    
    try:
        url = target if "://" in target else f"http://{target}"
        ctx = get_ssl_context(target, allow_insecure=True)
        
        for lang, payload in DESERIAL_PAYLOADS.items():
            try:
                req = urllib.request.Request(
                    url,
                    data=f"data={payload}".encode('utf-8'),
                    headers={
                        "User-Agent": "NEXUS-STRIKE/0.2.0 (Deserialization Detector)",
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    method="POST"
                )
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                body = resp.read(65536).decode("utf-8", errors="replace")
                
                # Check for common deserialization error patterns
                error_patterns = [
                    "java.io.InvalidClassException",
                    "PHP Fatal error: Uncaught Exception",
                    "pickle.UnpicklingError",
                    "AttributeError: Can't get attribute",
                    "gadget chain"
                ]
                
                for pattern in error_patterns:
                    if pattern.lower() in body.lower():
                        vuln_indicators.append({"lang": lang, "evidence": pattern})
                        findings.append(Finding(
                            title=f"Potential Insecure Deserialization ({lang.title()})",
                            severity="high",
                            confidence="medium",
                            affected_asset=url,
                            evidence=f"Deserialization error detected: {pattern}. This indicates the application may be processing untrusted serialized data.",
                            remediation="Avoid deserializing untrusted data. Use safe data formats like JSON. If deserialization is required, implement strict type checking and integrity verification (e.g., HMAC).",
                            tool="webapp.deserialization",
                            references=["CWE-502", "OWASP-A08"]
                        ))
                        break
            except Exception:
                pass
                
        summary = f"Deserialization testing completed. Found {len(vuln_indicators)} potential vulnerabilities."
        status = STATUS_COMPLETED if vuln_indicators else STATUS_NO_FINDINGS
        
    except Exception as e:
        return tool_result("webapp.deserialization", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "webapp.deserialization", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vuln_indicators}
    )

tool_registry.register("webapp.deserialization", run, metadata={
    "name": "webapp.deserialization",
    "domain": "webapp",
    "status": "completed",
    "description": "Insecure deserialization detection via Java/PHP/Python payload testing",
    "parameters": {"target": "Target URL accepting serialized data"},
})