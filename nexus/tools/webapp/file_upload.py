#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.file_upload
Domain: webapp
File-upload endpoint discovery (non-destructive: discovery only).

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", never looked for an upload endpoint).
Now: real OPTIONS/HEAD/GET probes of common upload endpoint paths to
confirm existence, without ever actually uploading a file. Deliberately
discovery-only per this platform's non-destructive-testing standard —
actually POSTing a file could create real server-side artifacts.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import urllib.error
import urllib.request
import urllib.parse
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Upload Endpoint Discovery)"

UPLOAD_PATHS = [
    "/upload", "/uploads", "/api/upload", "/api/v1/upload", "/file/upload",
    "/files/upload", "/admin/upload", "/wp-admin/async-upload.php",
    "/upload.php", "/uploadify/uploadify.php", "/media/upload",
    "/attachments/upload", "/api/files", "/api/media",
]


def _probe(url: str, timeout: int = 10, method: str = "OPTIONS") -> dict:
    """Make a real HTTP request (no body sent) and return status/headers."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method=method)
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()}, "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()}, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "error": str(e)[:100]}


def run(target: str, timeout: int = 10, paths: list[str] | None = None, **kwargs: Any) -> dict:
    """Discover file-upload endpoints without uploading anything.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    paths : list[str], optional
        Custom list of upload endpoint paths to try.
    """
    if not target or not target.strip():
        return tool_result("webapp.file_upload", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []
    discovered: list[dict] = []

    for path in (paths or UPLOAD_PATHS):
        endpoint = f"{root}{path}"
        resp = _probe(endpoint, timeout, method="OPTIONS")
        if resp["status"] in (0, 404):
            resp = _probe(endpoint, timeout, method="HEAD")
        if resp["status"] in (0, 404):
            continue

        allow = resp["headers"].get("allow", "")
        accepts_post = "post" in allow.lower() or resp["status"] in (200, 401, 403, 405)
        discovered.append({"path": path, "url": endpoint, "status": resp["status"], "allow": allow})
        findings.append(Finding(
            title=f"File upload endpoint discovered: {path}",
            severity="info",
            confidence="medium",
            affected_asset=endpoint,
            evidence=f"HTTP {resp['status']} at {endpoint}" + (f" (Allow: {allow})" if allow else "")
                     + (" — accepts POST" if accepts_post else ""),
            remediation="Confirm this endpoint enforces authentication, file-type/size validation, and stores uploads outside the web root. "
                        "(Discovery-only: no file was actually uploaded during this scan.)",
            tool="webapp.file_upload",
            references=["CWE-434"],
        ))

    status = STATUS_COMPLETED if discovered else STATUS_NO_FINDINGS
    summary = f"Upload endpoint discovery: {len(discovered)} endpoint(s) found (discovery-only, no files uploaded)" \
        if discovered else "Upload endpoint discovery: no upload endpoint found at common paths"

    return tool_result(
        "webapp.file_upload", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"discovered": discovered},
    )


tool_registry.register("webapp.file_upload", run, metadata={
    "name": "webapp.file_upload",
    "domain": "webapp",
    "status": "completed",
    "description": "Discovery-only file-upload endpoint enumeration via OPTIONS/HEAD probes of common paths (never uploads a file)",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "paths": "Custom list of upload endpoint paths to try",
    },
})
