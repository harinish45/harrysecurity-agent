#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.dir_enum
Domain: webapp
Directory and file enumeration with recursive scanning and status code analysis.
"""
from __future__ import annotations

import concurrent.futures
import re
import ssl
import urllib.request
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

USER_AGENT = "NEXUS-STRIKE/0.2.0 (DirEnum)"

COMMON_DIRS = [
    "/admin", "/wp-admin", "/administrator", "/backup", "/backups",
    "/config", "/conf", "/css", "/data", "/db", "/debug", "/demo", "/dev",
    "/download", "/downloads", "/email", "/error", "/examples", "/files",
    "/forum", "/images", "/img", "/inc", "/include", "/includes", "/index",
    "/install", "/js", "/lang", "/language", "/lib", "/library", "/login",
    "/logs", "/mail", "/manager", "/modules", "/news", "/old", "/panel",
    "/php", "/phpmyadmin", "/pma", "/private", "/restore", "/search",
    "/secret", "/secure", "/server-status", "/setup", "/sql", "/src",
    "/status", "/temp", "/test", "/tmp", "/upload", "/uploads", "/user",
    "/vendor", "/web", "/webadmin", "/webroot", "/www",
    ".env", ".git/config", ".git/HEAD", ".htaccess", ".htpasswd",
    "admin.php", "config.php", "config.php.bak", "db.php", "index.php",
    "info.php", "phpinfo.php", "settings.php", "wp-config.php",
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known/security.txt",
    "README.md", "CHANGELOG.md", "LICENSE", "composer.json", "package.json",
]


def _http_request(url: str, timeout: int = 5) -> dict:
    """Make HTTP request and return status and size."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(8192).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "size": len(body)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": "", "size": 0}
    except Exception:
        return {"status": 0, "body": "", "size": 0}


def _check_sensitive_files(content: str, url: str) -> list[Finding]:
    """Check directory listing or file content for sensitive data."""
    findings = []
    sensitive_patterns = {
        "database_creds": (r"(password|passwd|pwd)\s*[:=]", "Database credentials"),
        "api_key": (r"(api[_-]?key|apikey)\s*[:=]", "API key"),
        "private_key": (r"-----BEGIN.*PRIVATE KEY-----", "Private key"),
        "aws_key": (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        "database_url": (r"(mysql|postgres|mongodb|redis)://[^\s]+", "Database connection string"),
    }
    for pattern, desc in sensitive_patterns.items():
        if re.search(desc[1], content, re.IGNORECASE) if isinstance(desc, tuple) else False:
            pass
        if re.search(list(sensitive_patterns.values())[list(sensitive_patterns.keys()).index(pattern)][0], content, re.IGNORECASE):
            findings.append(Finding(
                title=f"Sensitive data exposed in {url}",
                severity="high",
                confidence="high",
                affected_asset=url,
                evidence=f"Found {list(sensitive_patterns.keys())[list(sensitive_patterns.keys()).index(pattern)]} pattern in response",
                remediation="Remove sensitive files or restrict access.",
                tool="webapp.dir_enum",
                references=["CWE-538", "CWE-200"],
            ))
    return findings


def run(
    target: str,
    wordlist: list[str] | None = None,
    max_checks: int = 100,
    timeout: int = 5,
    threads: int = 20,
    **kwargs: Any,
) -> dict:
    """Perform directory and file enumeration.

    Parameters
    ----------
    target : str
        Target hostname or URL to enumerate.
    wordlist : list[str], optional
        Custom wordlist for enumeration.
    max_checks : int
        Maximum paths to check.
    timeout : int
        Request timeout in seconds.
    threads : int
        Concurrent threads for scanning.
    """
    if not target or not target.strip():
        return tool_result("webapp.dir_enum", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    base = url.rstrip("/")
    findings: list[Finding] = []
    paths = wordlist or COMMON_DIRS[:max_checks]
    discovered: list[dict] = []

    def check_path(path: str) -> Optional[dict]:
        test_url = f"{base}{path}"
        resp = _http_request(test_url, timeout)
        if resp["status"] and resp["status"] not in (404,):
            return {"path": path, "status": resp["status"], "size": resp["size"], "url": test_url}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_path = {executor.submit(check_path, p): p for p in paths}
        for future in concurrent.futures.as_completed(future_to_path):
            result = future.result()
            if result:
                discovered.append(result)

    discovered.sort(key=lambda x: x["status"])

    for d in discovered:
        sev = "high" if d["path"] in [".env", ".git/config", "wp-config.php", "config.php.bak"] else \
              "medium" if d["status"] in (200,) else "low"
        findings.append(Finding(
            title=f"Directory/File discovered: {d['path']}",
            severity=sev,
            confidence="certain",
            affected_asset=d["url"],
            evidence=f"HTTP {d['status']}, Size: {d['size']} bytes",
            remediation="Review if this path should be publicly accessible.",
            tool="webapp.dir_enum",
            references=["CWE-538", "CWE-200"] if d["path"].startswith(".") or "config" in d["path"] else [],
        ))

    summary = f"Found {len(discovered)} paths in {len(paths)} checks"

    return tool_result(
        "webapp.dir_enum", target,
        status=STATUS_COMPLETED if discovered else STATUS_NO_FINDINGS,
        findings=findings,
        summary=summary,
        metadata={"checked": len(paths), "found": len(discovered), "discovered": discovered},
    )


tool_registry.register("webapp.dir_enum", run, metadata={
    "name": "webapp.dir_enum",
    "domain": "webapp",
    "status": "completed",
    "description": "Directory and file enumeration with status code analysis",
    "parameters": {
        "target": "Target hostname or URL",
        "wordlist": "Custom wordlist for enumeration",
        "max_checks": "Maximum paths to check (default: 100)",
        "timeout": "Request timeout in seconds (default: 5)",
        "threads": "Concurrent threads (default: 20)",
    },
})