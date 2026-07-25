#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.subdomain_enum
Domain: reconnaissance
Subdomain enumeration via DNS bruteforce, wordlist, and public sources.
"""
from __future__ import annotations

import socket
import json
import urllib.request
import urllib.error
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "imap", "pop", "ftp", "dns", "ns1", "ns2", "ns3",
    "api", "dev", "staging", "test", "prod", "production", "internal", "intranet",
    "admin", "administrator", "portal", "dashboard", "console", "login", "auth",
    "vpn", "gateway", "proxy", "cdn", "static", "assets", "images", "img",
    "blog", "shop", "store", "market", "wiki", "docs", "documentation",
    "support", "help", "status", "health", "monitor", "metrics",
    "jenkins", "ci", "build", "git", "svn", "repo", "bitbucket", "gitlab",
    "backup", "backups", "old", "legacy", "new", "news", "newsletters",
    "chat", "video", "stream", "streamtv", "download", "downloads",
]


def _dns_resolve(hostname: str) -> Optional[str]:
    """Resolve a hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout):
        return None


def _crtsh_query(domain: str, timeout: float = 5.0) -> list[str]:
    """Query crt.sh for subdomains from certificate transparency logs."""
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NEXUS-STRIKE/0.2.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        if sub and sub != domain:
                            subdomains.add(sub.lower().strip())
                return sorted(subdomains)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, socket.timeout):
        pass
    return []


def _securitytrails_query(domain: str, timeout: float = 5.0) -> list[str]:
    """Query SecurityTrails for subdomains (requires API key)."""
    try:
        import os
        api_key = os.getenv("SECURITYTRAILS_API_KEY", "")
        if not api_key:
            return []
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NEXUS-STRIKE/0.2.0", "APIKEY": api_key},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                return [f"{s}.{domain}" for s in data.get("subdomains", [])]
    except Exception:
        pass
    return []


def _hackertarget_query(domain: str, timeout: float = 5.0) -> list[str]:
    """Query HackerTarget API for subdomains (public endpoint)."""
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NEXUS-STRIKE/0.2.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                text = resp.read().decode("utf-8", errors="replace")
                subdomains = []
                for line in text.strip().split("\n"):
                    if "," in line:
                        parts = line.split(",")
                        if len(parts) >= 1:
                            subdomains.append(parts[0].strip().lower())
                return [s for s in subdomains if s != domain]
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout):
        pass
    return []


def run(
    target: str,
    wordlist: list[str] | None = None,
    use_crtsh: bool = True,
    use_hackertarget: bool = True,
    use_securitytrails: bool = False,
    timeout: float = 5.0,
    **kwargs: Any,
) -> dict:
    """Enumerate subdomains for a domain.

    Parameters
    ----------
    target : str
        Domain name to enumerate subdomains for.
    wordlist : list[str], optional
        Custom subdomain wordlist to bruteforce.
    use_crtsh : bool
        Query certificate transparency logs.
    use_hackertarget : bool
        Query public HackerTarget API.
    use_securitytrails : bool
        Query SecurityTrails API (requires API key).
    timeout : float
        HTTP request timeout in seconds.
    """
    domain = target.strip().lower()
    if not domain:
        return tool_result("reconnaissance.subdomain_enum", target, status=STATUS_FAILED, error="Empty target")

    if "." not in domain or domain.startswith("."):
        return tool_result("reconnaissance.subdomain_enum", target, status=STATUS_FAILED, error=f"Invalid domain: {domain}")

    findings: list[Finding] = []
    discovered: dict[str, str] = {}

    subdomain_list = wordlist or COMMON_SUBDOMAINS

    for sub in subdomain_list:
        hostname = f"{sub}.{domain}"
        ip = _dns_resolve(hostname)
        if ip:
            discovered[hostname] = ip

    if use_crtsh and len(discovered) < 50:
        crtsh_subs = _crtsh_query(domain, timeout)
        for sub in crtsh_subs:
            if sub not in discovered:
                ip = _dns_resolve(sub)
                if ip:
                    discovered[sub] = ip

    if use_hackertarget and len(discovered) < 50:
        ht_subs = _hackertarget_query(domain, timeout)
        for sub in ht_subs:
            if sub not in discovered:
                ip = _dns_resolve(sub)
                if ip:
                    discovered[sub] = ip

    if use_securitytrails:
        st_subs = _securitytrails_query(domain, timeout)
        for sub in st_subs:
            if sub not in discovered:
                ip = _dns_resolve(sub)
                if ip:
                    discovered[sub] = ip

    if discovered:
        for hostname, ip in sorted(discovered.items()):
            findings.append(Finding(
                title=f"Discovered subdomain: {hostname}",
                severity="info",
                confidence="high",
                affected_asset=hostname,
                evidence=f"DNS A record: {hostname} -> {ip}",
                remediation="Verify subdomain is intended to be publicly accessible.",
                tool="reconnaissance.subdomain_enum",
                references=["CWE-200"],
            ))

        return tool_result(
            "reconnaissance.subdomain_enum", target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Discovered {len(discovered)} subdomains for {domain}",
            metadata={"subdomain_count": len(discovered)},
        )

    return tool_result(
        "reconnaissance.subdomain_enum", target,
        status=STATUS_NO_FINDINGS,
        summary=f"No subdomains discovered for {domain}",
        metadata={"subdomain_count": 0},
    )


tool_registry.register("reconnaissance.subdomain_enum", run, metadata={
    "name": "reconnaissance.subdomain_enum",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Subdomain enumeration via DNS bruteforce and public sources",
    "parameters": {
        "target": "Target domain to enumerate",
        "wordlist": "Custom subdomain wordlist to bruteforce",
        "use_crtsh": "Query certificate transparency logs (default: True)",
        "use_hackertarget": "Query public HackerTarget API (default: True)",
        "use_securitytrails": "Query SecurityTrails API if key available (default: False)",
        "timeout": "HTTP request timeout in seconds (default: 5s)",
    },
})
