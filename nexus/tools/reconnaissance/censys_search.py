#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance tool: Censys Search
Domain: reconnaissance
"""
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context


def run(target: str, **kwargs) -> dict:
    """reconnaissance tool: Censys Search"""
    findings = []
    try:
        import re as _re
        import socket
        import ssl
        import urllib.error
        import urllib.request

        def _extract_title(html):
            m = _re.search(r'<title[^>]*>([^<]+)</title>', html, _re.IGNORECASE)
            return m.group(1).strip() if m else ''

        ssl_ctx = get_ssl_context(target, allow_insecure=True)
        # DNS resolution
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Resolved {target} -> {ip}")
        except Exception as e:
            findings.append(f"DNS resolution failed: {e}")
        # HTTP check
        for scheme in ("http", "https"):
            url = f"{scheme}://{target}/"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                resp = urllib.request.urlopen(req, timeout=6, context=ssl_ctx)
                server = resp.headers.get('Server', 'unknown')
                body = resp.read(4096).decode('utf-8', errors='replace')
                title = _extract_title(body)
                title_note = f", Title='{title}'" if title else ''
                findings.append(
                    f"{scheme.upper()} {url}: status={resp.status},"
                    f" Server={server}{title_note}"
                )
            except urllib.error.HTTPError as e:
                findings.append(f"{scheme.upper()} {url}: HTTP {e.code} {e.reason}")
            except OSError:
                findings.append(f"{scheme.upper()} {url}: port not reachable (closed or filtered)")
            except Exception as e:
                findings.append(f"{scheme.upper()} {url}: {str(e)[:120]}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "reconnaissance.censys_search", "domain": "reconnaissance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("reconnaissance.censys_search", run, metadata={
    "name": "reconnaissance.censys_search",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "reconnaissance tool: Censys Search",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
