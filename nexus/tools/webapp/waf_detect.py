#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp tool: Waf Detect
Domain: webapp
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """webapp tool: Waf Detect"""
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
            import re as _re
            def _title(h):
                m = _re.search(r'<title[^>]*>([^<]+)</title>', h, _re.IGNORECASE)
                return m.group(1).strip() if m else ''
            server = resp.headers.get('Server', 'unknown')
            powered_by = resp.headers.get('X-Powered-By', '')
            csp = resp.headers.get('Content-Security-Policy', 'missing')
            hsts = resp.headers.get('Strict-Transport-Security', 'missing')
            x_frame = resp.headers.get('X-Frame-Options', 'missing')
            body = resp.read(4096).decode('utf-8', errors='replace')
            title = _title(body)
            findings.append(
                f"HTTP {resp.status} {url}: Server={server}"
                + (f", X-Powered-By={powered_by}" if powered_by else "")
                + (f", Title='{title}'" if title else "")
            )
            findings.append(f"Security headers — CSP={csp}, HSTS={hsts}, X-Frame-Options={x_frame}")
            if csp == 'missing':
                findings.append('WARN: Content-Security-Policy header absent')
            if hsts == 'missing':
                findings.append('WARN: Strict-Transport-Security header absent')
            if x_frame == 'missing':
                findings.append('WARN: X-Frame-Options header absent (potential clickjacking)')
        except urllib.error.HTTPError as e:
            findings.append(f"HTTP {e.code}: {url}")
        except Exception as e:
            findings.append(f"HTTP error: {str(e)[:80]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "webapp.waf_detect", "domain": "webapp", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("webapp.waf_detect", run, metadata={
    "name": "webapp.waf_detect",
    "domain": "webapp",
    "status": "completed",
    "description": "webapp tool: Waf Detect",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
