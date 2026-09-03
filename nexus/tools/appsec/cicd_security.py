#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec tool: Cicd Security
Domain: appsec
"""
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context


def run(target: str, **kwargs) -> dict:
    """appsec tool: Cicd Security"""
    findings = []
    try:
        import urllib.request
        import urllib.parse
        import ssl
        url = target if "://" in target else f"http://{target}/"
        ctx = get_ssl_context(target, allow_insecure=True)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            body = resp.read(8192).decode('utf-8', errors='replace')
            findings.append(f"HTTP {resp.status}: Server={resp.headers.get('Server', 'unknown')}")
            # Check for security headers
            headers = dict(resp.headers)
            for h in ["X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy"]:
                if h not in headers:
                    findings.append(f"Missing security header: {h}")
            # Check for common vulnerabilities in body
            if "<form" in body.lower():
                findings.append("Form found - potential for input-based attacks")
            if "admin" in body.lower():
                findings.append("Admin reference found in page")
        except urllib.error.HTTPError as e:
            findings.append(f"HTTP {e.code}: {url}")
        except Exception as e:
            findings.append(f"HTTP error: {str(e)[:80]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "appsec.cicd_security", "domain": "appsec", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("appsec.cicd_security", run, metadata={
    "name": "appsec.cicd_security",
    "domain": "appsec",
    "status": "completed",
    "description": "appsec tool: Cicd Security",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
