#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance tool: Github Recon
Domain: reconnaissance
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """reconnaissance tool: Github Recon"""
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

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
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
    return {"tool": "reconnaissance.github_recon", "domain": "reconnaissance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("reconnaissance.github_recon", run, metadata={
    "name": "reconnaissance.github_recon",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "reconnaissance tool: Github Recon",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
