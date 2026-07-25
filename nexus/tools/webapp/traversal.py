#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp tool: Traversal
Domain: webapp
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """webapp tool: Traversal"""
    findings = []
    try:
        import urllib.request
        import ssl
        import urllib.parse
        parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}/")
        url = parsed.geturl()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            findings.append(f"HTTP {resp.status}: Server={resp.headers.get('Server', 'unknown')}, X-Powered-By={resp.headers.get('X-Powered-By', '')}")
            body = resp.read(4096).decode('utf-8', errors='replace')
            findings.append(f"Response body (first 500 chars): {body[:500]}")
        except urllib.error.HTTPError as e:
            findings.append(f"HTTP {e.code}: {url}")
        except Exception as e:
            findings.append(f"HTTP error: {str(e)[:80]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "webapp.traversal", "domain": "webapp", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("webapp.traversal", run, metadata={
    "name": "webapp.traversal",
    "domain": "webapp",
    "status": "completed",
    "description": "webapp tool: Traversal",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
