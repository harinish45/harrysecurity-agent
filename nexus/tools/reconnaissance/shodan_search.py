#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.shodan_search
Domain: reconnaissance

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to Shodan at all). Caught
during a follow-up audit and rewritten to require a paid Shodan API key.

Follow-up fix (making the platform runnable free-tier-only): Shodan
operates a genuinely free, unauthenticated endpoint — InternetDB
(https://internetdb.shodan.io/<ip>) — that returns real open-ports,
hostnames, CPEs, and known-CVE data for an IP with zero cost and no key.
That's now the DEFAULT path. If SHODAN_API_KEY *is* configured, the full
paid Search API is used instead for richer banner/product data — an
optional enhancement, never a requirement.
"""
from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_TOOL_NAME = "reconnaissance.shodan_search"
_USER_AGENT = "NEXUS-STRIKE/0.2.0 (ShodanSearch)"


def _resolve_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target  # already an IP, or unresolvable — let the API report that


def _run_internetdb(target: str, ip: str) -> dict:
    """Free, unauthenticated Shodan InternetDB lookup — no API key required."""
    try:
        url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        ctx = get_ssl_context("internetdb.shodan.io")
        resp = safe_urlopen(req, timeout=12, context=ctx)
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return tool_result(
                _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
                summary=f"Shodan InternetDB (free) has no indexed data for {ip}",
            )
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE,
                            error=f"Shodan InternetDB HTTP {e.code}: {e.reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE,
                            error=f"Shodan InternetDB unreachable: {e}")
    except (json.JSONDecodeError, ValueError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"unparseable InternetDB response: {e}")

    findings: list[Finding] = []
    ports = data.get("ports", []) or []
    hostnames = data.get("hostnames", []) or []
    cpes = data.get("cpes", []) or []
    vulns = sorted(data.get("vulns", []) or [])

    if ports:
        findings.append(Finding(
            title=f"Shodan-indexed open ports on {ip} (free InternetDB lookup)",
            severity="info",
            confidence="certain",
            affected_asset=ip,
            evidence=f"Shodan InternetDB reports {len(ports)} open port(s): {ports}"
                     + (f"; associated hostnames: {hostnames}" if hostnames else "")
                     + (f"; fingerprinted software (CPEs): {cpes}" if cpes else ""),
            remediation="Confirm each exposed port is intentional and properly hardened/patched; "
                        "restrict access if it shouldn't be internet-facing.",
            tool=_TOOL_NAME,
            references=[f"https://www.shodan.io/host/{ip}"],
        ))

    if vulns:
        findings.append(Finding(
            title=f"Shodan-flagged known CVEs on {ip} (free InternetDB lookup)",
            severity="high",
            confidence="high",
            affected_asset=ip,
            evidence=f"Shodan's InternetDB associates these CVEs with {ip}: {vulns}",
            remediation="Patch or mitigate the listed CVEs; verify Shodan's fingerprint accuracy against "
                        "the actual running software versions.",
            tool=_TOOL_NAME,
            references=[f"https://nvd.nist.gov/vuln/detail/{v}" for v in vulns[:10]],
        ))

    if not findings:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"Shodan InternetDB (free) has indexed {ip} but reported no open ports/CVEs",
            metadata={"shodan_ports": ports, "source": "internetdb_free"},
        )

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Shodan InternetDB (free, no API key) lookup for {ip} found {len(ports)} open port(s) "
                f"and {len(vulns)} known CVE(s)",
        metadata={"shodan_ports": ports, "shodan_vulns": vulns, "source": "internetdb_free"},
    )


def _run_full_api(target: str, ip: str, api_key: str) -> dict:
    """Paid Shodan Search API host-lookup — richer banner/product data than InternetDB."""
    try:
        url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}?key={urllib.parse.quote(api_key)}"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        ctx = get_ssl_context("api.shodan.io")
        resp = safe_urlopen(req, timeout=12, context=ctx)
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return tool_result(_TOOL_NAME, target, status=STATUS_NO_FINDINGS,
                                summary=f"Shodan (paid API) has no indexed data for {ip}")
        if e.code == 401:
            # Bad/expired key — fall back to the free path rather than hard-fail.
            return _run_internetdb(target, ip)
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE,
                            error=f"Shodan API HTTP {e.code}: {e.reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE, error=f"Shodan API unreachable: {e}")
    except (json.JSONDecodeError, ValueError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"unparseable Shodan response: {e}")

    findings: list[Finding] = []
    ports = data.get("ports", []) or []
    for service in data.get("data", []) or []:
        port = service.get("port")
        product = service.get("product", "") or service.get("_shodan", {}).get("module", "unknown")
        banner = (service.get("data") or "")[:300]
        findings.append(Finding(
            title=f"Shodan-indexed service on {ip}:{port}",
            severity="info",
            confidence="certain",
            affected_asset=f"{ip}:{port}",
            evidence=f"Shodan reports {product or 'unknown service'} on port {port}. Banner: {banner!r}",
            remediation="Confirm this exposed service is intentional and properly hardened/patched; "
                        "restrict access if it shouldn't be internet-facing.",
            tool=_TOOL_NAME,
            references=[f"https://www.shodan.io/host/{ip}"],
        ))

    vulns = sorted(data.get("vulns", []) or [])
    if vulns:
        findings.append(Finding(
            title=f"Shodan-flagged known CVEs on {ip}",
            severity="high",
            confidence="high",
            affected_asset=ip,
            evidence=f"Shodan's vulnerability database associates these CVEs with {ip}: {vulns}",
            remediation="Patch or mitigate the listed CVEs; verify Shodan's fingerprint accuracy against "
                        "the actual running software versions.",
            tool=_TOOL_NAME,
            references=[f"https://nvd.nist.gov/vuln/detail/{v}" for v in vulns[:10]],
        ))

    if not findings:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"Shodan (paid API) has indexed {ip} but reported no open services",
            metadata={"shodan_ports": ports, "source": "full_api"},
        )

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Shodan full-API lookup for {ip} found {len(ports)} indexed port(s) and {len(vulns)} known CVE(s)",
        metadata={"shodan_ports": ports, "shodan_vulns": vulns, "source": "full_api"},
    )


def run(target: str, **kwargs: Any) -> dict:
    """Real Shodan host-lookup. Free by default via InternetDB (no key needed); uses the
    paid Search API for richer data only when SHODAN_API_KEY is actually configured."""
    ip = _resolve_ip(target)
    api_key = kwargs.get("shodan_api_key") or os.environ.get("SHODAN_API_KEY")
    if api_key:
        return _run_full_api(target, ip, api_key)
    return _run_internetdb(target, ip)


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Real Shodan host lookup — free by default (InternetDB, no API key needed); "
                    "uses the paid Shodan Search API for richer banner data only if SHODAN_API_KEY is set",
    "parameters": {
        "target": "Target domain or IP to look up in Shodan",
        "shodan_api_key": "(optional, paid) SHODAN_API_KEY env var or this kwarg — enables the fuller "
                           "paid Search API; the free InternetDB lookup is used automatically without it",
    },
})
