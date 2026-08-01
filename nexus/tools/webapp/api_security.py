#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp tool: Api Security
Domain: webapp
"""
from nexus.tools.registry import tool_registry


def _extract_title(html: str) -> str:
    """Extract <title> text from an HTML string."""
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def run(target: str, **kwargs) -> dict:
    """webapp tool: Api Security"""
    findings = []
    try:
        import urllib.request
        import urllib.error
        import ssl
        import urllib.parse

        parsed = urllib.parse.urlparse(
            target if "://" in target else f"http://{target}/"
        )
        url = parsed.geturl()

        # Permissive SSL — don't fail on self-signed / missing certs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "NexusStrike/1.0"}
            )
            resp = urllib.request.urlopen(req, timeout=6, context=ctx)
            server = resp.headers.get("Server", "unknown")
            powered_by = resp.headers.get("X-Powered-By", "")
            csp = resp.headers.get("Content-Security-Policy", "missing")
            hsts = resp.headers.get("Strict-Transport-Security", "missing")
            x_frame = resp.headers.get("X-Frame-Options", "missing")

            body = resp.read(4096).decode("utf-8", errors="replace")
            title = _extract_title(body)

            findings.append(
                f"HTTP {resp.status} {url}: Server={server}"
                + (f", X-Powered-By={powered_by}" if powered_by else "")
                + (f", Title='{title}'" if title else "")
            )
            findings.append(f"Security headers — CSP={csp}, HSTS={hsts}, X-Frame-Options={x_frame}")

            # Flag obviously missing security headers
            if csp == "missing":
                findings.append("WARN: Content-Security-Policy header absent")
            if hsts == "missing":
                findings.append("WARN: Strict-Transport-Security header absent")
            if x_frame == "missing":
                findings.append("WARN: X-Frame-Options header absent (potential clickjacking)")

        except urllib.error.HTTPError as http_err:
            findings.append(f"HTTP {http_err.code} {http_err.reason}: {url}")
        except OSError:
            findings.append(f"Connection refused / port not reachable: {url}")
        except Exception as probe_err:
            findings.append(f"HTTP error: {str(probe_err)[:120]}")
    except Exception as outer_err:
        findings.append(f"Error: {outer_err}")
    return {
        "tool": "webapp.api_security",
        "domain": "webapp",
        "target": target,
        "status": "completed",
        "findings": findings,
    }


# Register with tool registry
tool_registry.register("webapp.api_security", run, metadata={
    "name": "webapp.api_security",
    "domain": "webapp",
    "status": "completed",
    "description": "webapp tool: Api Security",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
