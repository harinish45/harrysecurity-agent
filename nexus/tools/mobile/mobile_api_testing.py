#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tool: Mobile Api Testing
Domain: mobile

Unlike the other mobile.* tools, mobile API testing is genuinely
network-observable: mobile apps talk to a backend API over HTTP(S), so this
tool can (and should) run real, safe HTTP probes against a URL/domain
target — the same style as nexus/tools/webapi/*.py. This previously
ignored `target`'s actual API surface and instead tried (and failed, for
any non-.apk target) to treat it as a local APK file, reporting status
"completed" regardless — caught during an audit alongside
hardware.usb_attacks. It now issues real safe_urlopen requests against
mobile-API-shaped paths and compares mobile-vs-browser User-Agent
responses, honestly degrading when the target is unreachable or is itself
a mobile app file (out of scope for this tool — see apk_decompilation/
ipa_analysis for that).
"""
from __future__ import annotations

import urllib.error
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_MOBILE_UA = "MyApp/3.2.1 (Linux; Android 13; Dalvik/2.1.0)"
_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

_MOBILE_API_PATHS = ["/api/mobile", "/mobile/api", "/api/v1", "/api/v2", "/api"]


def _probe(url: str, ua: str, ctx) -> dict:
    entry = {"url": url, "user_agent": ua}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        resp = safe_urlopen(req, timeout=6, context=ctx)
        entry["status"] = resp.status
        entry["headers"] = dict(resp.getheaders())
        entry["body_len"] = len(resp.read(4096))
        entry["reachable"] = True
    except urllib.error.HTTPError as e:
        entry["status"] = e.code
        entry["headers"] = dict(e.headers.items()) if e.headers else {}
        entry["reachable"] = True
    except Exception as e:
        entry["error"] = str(e)
        entry["reachable"] = False
    return entry


def run(target: str, **kwargs) -> dict:
    """mobile tool: real HTTP-based probing of mobile-API-shaped endpoints
    (versioning, mobile-identifying header/UA differential response)."""
    if not isinstance(target, str) or not target:
        return tool_result(
            "mobile.mobile_api_testing", target,
            status=STATUS_OUT_OF_SCOPE,
            summary="Mobile API testing requires a URL/domain target",
            error="out_of_scope: empty target",
        )
    if target.lower().endswith(".apk") or target.lower().endswith(".ipa"):
        return tool_result(
            "mobile.mobile_api_testing", target,
            status=STATUS_OUT_OF_SCOPE,
            summary="Mobile API testing operates against a network endpoint (URL/domain), not a local app file",
            error="out_of_scope: target is a local .apk/.ipa file — use apk_decompilation/android_analysis "
                  "or ipa_analysis/ios_analysis for file-based targets",
        )

    base = target if "://" in target else f"http://{target}"
    ctx = get_ssl_context(target, allow_insecure=True)

    root_mobile = _probe(base.rstrip("/") + "/", _MOBILE_UA, ctx)
    root_browser = _probe(base.rstrip("/") + "/", _BROWSER_UA, ctx)

    if not root_mobile["reachable"] and not root_browser["reachable"]:
        return tool_result(
            "mobile.mobile_api_testing", target,
            status=STATUS_FAILED,
            summary=f"{base} was not reachable over HTTP(S)",
            error=root_mobile.get("error", "unreachable"),
            metadata={"root_mobile": root_mobile, "root_browser": root_browser},
        )

    probed = [root_mobile]
    for path in _MOBILE_API_PATHS:
        probed.append(_probe(base.rstrip("/") + path, _MOBILE_UA, ctx))

    findings: list[Finding] = []

    versioned_hits = [p for p in probed if p.get("reachable") and p["url"].rstrip("/").endswith(("/api/v1", "/api/v2"))
                       and p.get("status") in (200, 401, 403)]
    unversioned_api_hits = [p for p in probed if p.get("reachable") and p["url"].rstrip("/").endswith("/api")
                             and p.get("status") in (200, 401, 403)]
    if unversioned_api_hits and not versioned_hits:
        findings.append(Finding(
            title="API reachable without version namespacing",
            severity="low",
            confidence="medium",
            affected_asset=base,
            evidence=f"{unversioned_api_hits[0]['url']} responded {unversioned_api_hits[0]['status']} "
                     f"but no /api/v1 or /api/v2 namespace was found",
            remediation="Adopt explicit API versioning (e.g. /api/v1/...) so breaking changes to the "
                        "mobile client's API surface can be rolled out safely.",
            references=["OWASP-API9"],
            tool="mobile.mobile_api_testing",
        ))

    mobile_shaped_hits = [p for p in probed[1:] if p.get("reachable") and p.get("status") in (200, 401, 403)]
    for hit in mobile_shaped_hits:
        findings.append(Finding(
            title=f"Mobile-API-shaped endpoint responded: {hit['url']}",
            severity="info",
            confidence="high",
            affected_asset=hit["url"],
            evidence=f"HTTP {hit['status']} with User-Agent={_MOBILE_UA!r}",
            remediation="Confirm this endpoint enforces the same authentication/authorization as the "
                        "primary web API — mobile-specific API paths are frequently under-tested.",
            tool="mobile.mobile_api_testing",
        ))

    if root_mobile.get("reachable") and root_browser.get("reachable") and root_mobile.get("status") != root_browser.get("status"):
        findings.append(Finding(
            title="Response differs by User-Agent (mobile vs. desktop browser)",
            severity="low",
            confidence="medium",
            affected_asset=base,
            evidence=f"Mobile UA -> {root_mobile.get('status')}, Browser UA -> {root_browser.get('status')}",
            remediation="Review User-Agent-based routing/content-negotiation logic for inconsistent "
                        "security controls between the mobile and web code paths.",
            tool="mobile.mobile_api_testing",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "mobile.mobile_api_testing", target,
        status=status,
        findings=findings,
        summary=f"Probed {len(probed)} mobile-API-shaped path(s) against {base}; "
                f"{len(mobile_shaped_hits)} reachable, {len(findings)} finding(s)",
        metadata={"probed": probed, "root_browser": root_browser},
    )


# Register with tool registry
tool_registry.register("mobile.mobile_api_testing", run, metadata={
    "name": "mobile.mobile_api_testing",
    "domain": "mobile",
    "status": "completed",
    "description": "Real HTTP-based mobile-API surface probing (versioning, mobile-shaped paths, "
                    "mobile-vs-browser User-Agent differential response)",
    "parameters": {
        "target": "Target domain or URL (the backend a mobile app talks to)",
    },
})
