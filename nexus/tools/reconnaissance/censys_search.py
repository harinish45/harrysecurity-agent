#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.censys_search
Domain: reconnaissance

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to Censys at all). Caught
during a follow-up audit and rewritten against the legacy
search.censys.io/api/v2 Basic-Auth API.

Follow-up fix (making the platform runnable free-tier-only): Censys has
since migrated free accounts to the "Censys Platform" API
(api.platform.censys.io/v3), which the old v2 Basic-Auth endpoint no
longer serves for free users. Free accounts get 100 lookup credits/month
via a Personal Access Token that costs nothing to create (no payment
method required) — this is a free tier gated by a free signup, not a
paid subscription, and the tool's messaging now says so explicitly.
Live behavior against the new endpoint is unverified in this environment
(no Censys account/token available to test against) — error handling
degrades honestly (STATUS_UNAVAILABLE/STATUS_FAILED) on any unexpected
response shape rather than crashing or fabricating results.
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
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_TOOL_NAME = "reconnaissance.censys_search"
_USER_AGENT = "NEXUS-STRIKE/0.2.0 (CensysSearch)"
_API_BASE = "https://api.platform.censys.io/v3/global/asset/host"


def run(target: str, **kwargs: Any) -> dict:
    """Real Censys Platform API host lookup — requires a free Personal Access Token
    (no cost, no payment method; sign up at censys.com). Honest degrade without one."""
    token = kwargs.get("censys_pat") or os.environ.get("CENSYS_PAT") or os.environ.get("CENSYS_API_TOKEN")
    if not token:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_REQUIRES_CREDENTIALS,
            summary="Censys host lookup requires a Personal Access Token (CENSYS_PAT env var or "
                    "censys_pat kwarg) — this is FREE to create (100 lookup credits/month, no "
                    "payment method required, sign up at https://platform.censys.io), just not "
                    "anonymous/no-auth like Shodan's InternetDB. None provided, no data fabricated.",
            error="missing Censys Personal Access Token",
        )

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"DNS resolution failed: {e}")

    try:
        url = f"{_API_BASE}/{urllib.parse.quote(ip)}"
        req = urllib.request.Request(url, headers={
            "User-Agent": _USER_AGENT,
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        ctx = get_ssl_context("api.platform.censys.io")
        resp = safe_urlopen(req, timeout=12, context=ctx)
        body = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return tool_result(_TOOL_NAME, target, status=STATUS_NO_FINDINGS, summary=f"Censys has no indexed data for {ip}")
        if e.code in (401, 403):
            return tool_result(
                _TOOL_NAME, target, status=STATUS_REQUIRES_CREDENTIALS,
                summary=f"Censys API rejected the provided Personal Access Token (HTTP {e.code})",
            )
        if e.code == 429:
            return tool_result(
                _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
                summary="Censys API rate/credit limit reached (free tier: 100 lookups/month)",
            )
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE, error=f"Censys API HTTP {e.code}: {e.reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_UNAVAILABLE, error=f"Censys API unreachable: {e}")
    except (json.JSONDecodeError, ValueError) as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"unparseable Censys response: {e}")

    # Platform API v3 response shape: best-effort extraction, tolerant of the
    # nesting varying by response envelope version — never assume a single
    # fixed shape and crash if the API evolves.
    result = body if isinstance(body, dict) else {}
    for key in ("result", "asset", "host"):
        if isinstance(result.get(key), dict):
            result = result[key]
    services = result.get("services", []) or result.get("open_ports", []) or []

    if not services:
        return tool_result(_TOOL_NAME, target, status=STATUS_NO_FINDINGS, summary=f"Censys indexed {ip} but found no open services")

    findings: list[Finding] = []
    for svc in services:
        if isinstance(svc, int):
            svc = {"port": svc}
        port = svc.get("port")
        service_name = svc.get("service_name") or svc.get("protocol") or "unknown"
        software = svc.get("software", []) or []
        software_str = ", ".join(
            f"{s.get('product', '')} {s.get('version', '')}".strip() for s in software if isinstance(s, dict)
        ) or "unidentified"
        findings.append(Finding(
            title=f"Censys-indexed {service_name} service on {ip}:{port}",
            severity="info",
            confidence="certain",
            affected_asset=f"{ip}:{port}",
            evidence=f"Censys reports {service_name} on port {port}, software: {software_str}",
            remediation="Confirm this exposed service is intentional and properly hardened/patched.",
            tool=_TOOL_NAME,
            references=[f"https://platform.censys.io/hosts/{ip}"],
        ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Censys lookup for {ip} found {len(services)} indexed service(s)",
        metadata={"censys_service_count": len(services)},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Real Censys Platform API host lookup — requires a FREE Personal Access Token "
                    "(100 lookups/month, no payment method needed, not a paid subscription); "
                    "reports requires_credentials honestly when no token is available",
    "parameters": {
        "target": "Target domain or IP to look up in Censys",
        "censys_pat": "(optional if CENSYS_PAT env var is set) Censys Personal Access Token — free to create",
    },
})
