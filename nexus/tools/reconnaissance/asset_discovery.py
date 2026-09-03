#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance tool: Asset Discovery
Domain: reconnaissance
"""
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context


def _extract_title(html: str) -> str:
    """Extract <title> text from an HTML string."""
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def run(target: str, **kwargs) -> dict:
    """reconnaissance tool: Asset Discovery"""
    findings = []
    try:
        import socket
        import ssl
        import urllib.request
        import urllib.error

        # Build a permissive SSL context (ignore self-signed / untrusted certs)
        ssl_ctx = get_ssl_context(target, allow_insecure=True)

        # DNS resolution
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Resolved {target} -> {ip}")
        except Exception as dns_err:
            findings.append(f"DNS resolution failed: {dns_err}")

        # HTTP/HTTPS probing
        for scheme in ("http", "https"):
            url = f"{scheme}://{target}/"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "NexusStrike/1.0"}
                )
                resp = urllib.request.urlopen(req, timeout=6, context=ssl_ctx)
                server = resp.headers.get("Server", "unknown")
                body = resp.read(4096).decode("utf-8", errors="replace")
                title = _extract_title(body)
                title_note = f", Title='{title}'" if title else ""
                findings.append(
                    f"{scheme.upper()} {url}: status={resp.status}, "
                    f"Server={server}{title_note}"
                )
            except urllib.error.HTTPError as http_err:
                findings.append(f"{scheme.upper()} {url}: HTTP {http_err.code} {http_err.reason}")
            except OSError:
                # Port closed / connection refused / network unreachable
                findings.append(f"{scheme.upper()} {url}: port not reachable (closed or filtered)")
            except Exception as probe_err:
                findings.append(f"{scheme.upper()} {url}: {str(probe_err)[:120]}")
    except Exception as outer_err:
        findings.append(f"Error: {outer_err}")
    return {
        "tool": "reconnaissance.asset_discovery",
        "domain": "reconnaissance",
        "target": target,
        "status": "completed",
        "findings": findings,
    }


# Register with tool registry
tool_registry.register("reconnaissance.asset_discovery", run, metadata={
    "name": "reconnaissance.asset_discovery",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "reconnaissance tool: Asset Discovery",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
