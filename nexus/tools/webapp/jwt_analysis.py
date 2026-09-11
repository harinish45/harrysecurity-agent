#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.jwt_analysis
Domain: webapp
Passive JWT discovery and structural weakness analysis.

Previously: a dummy stub identical across all 17 webapp.* "secondary" tools
(DNS resolve + bare GET of "/", never looked for a token at all).
Now: a real GET of the target that scans the response headers, Set-Cookie
values, and response body for an ``eyJ``-shaped JWT, decodes its header and
payload (base64url), and flags structural weaknesses: ``alg: none``,
HS256/HS384/HS512 (susceptible to secret brute-forcing or RS256->HS256
confusion — see webapp.jwt_attacks for active exploitation of that), a
missing/expired ``exp`` claim, and sensitive-looking claims transmitted
unencrypted (JWTs are base64, not encrypted).

This tool is discovery/analysis only; webapp.jwt_attacks performs the
active forgery attempts against a discovered or supplied token.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import base64
import json
import re
import time
import urllib.error
import urllib.request
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (JWT Analyzer)"

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

WEAK_ALGS = {"none", "hs256", "hs384", "hs512"}


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET and return status/headers/cookies/body."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(131072).decode("utf-8", errors="replace")
        cookies = resp.headers.get_all("Set-Cookie") or []
        return {"status": resp.status, "headers": dict(resp.headers), "cookies": cookies, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(131072).decode("utf-8", errors="replace") if e.fp else ""
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        return {"status": e.code, "headers": dict(e.headers or {}), "cookies": cookies or [], "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "cookies": [], "body": "", "error": str(e)[:100]}


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _find_tokens(resp: dict) -> list[dict]:
    """Search headers, cookies, and body for JWT-shaped tokens."""
    found = []
    haystacks = [("body", resp.get("body", ""))]
    for header, value in (resp.get("headers") or {}).items():
        haystacks.append((f"header:{header}", str(value)))
    for cookie in resp.get("cookies") or []:
        haystacks.append(("cookie", cookie))

    seen = set()
    for source, text in haystacks:
        for match in JWT_PATTERN.finditer(text):
            token = match.group(0)
            if token in seen:
                continue
            seen.add(token)
            found.append({"source": source, "token": token})
    return found


def _decode_token(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace")) if parts[1] else {}
        return {"header": header, "payload": payload}
    except Exception:
        return None


def run(target: str, timeout: int = 10, **kwargs: Any) -> dict:
    """Discover and analyze JWTs exposed by target.

    Parameters
    ----------
    target : str
        URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.jwt_analysis", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    resp = _http_request(url, timeout)

    if resp["status"] == 0:
        return tool_result("webapp.jwt_analysis", target, status=STATUS_FAILED, error=resp.get("error") or "Connection failed")

    tokens = _find_tokens(resp)
    analyzed: list[dict] = []

    for entry in tokens:
        decoded = _decode_token(entry["token"])
        if not decoded:
            continue
        header = decoded["header"]
        payload = decoded["payload"]
        alg = str(header.get("alg", "")).lower()
        analyzed.append({"source": entry["source"], "alg": header.get("alg"), "header": header, "claims": list(payload.keys())})

        if alg == "none":
            findings.append(Finding(
                title=f"JWT found with alg='none' (source: {entry['source']})",
                severity="critical",
                confidence="high",
                affected_asset=url,
                evidence=f"Header: {json.dumps(header)}",
                remediation="Never accept unsigned ('none' algorithm) JWTs; enforce an algorithm allow-list server-side.",
                tool="webapp.jwt_analysis",
                references=["CWE-347", "CVE-2015-9235"],
            ))
        elif alg in WEAK_ALGS:
            findings.append(Finding(
                title=f"JWT uses HMAC algorithm '{header.get('alg')}' (source: {entry['source']})",
                severity="medium",
                confidence="medium",
                affected_asset=url,
                evidence=f"Header: {json.dumps(header)} — HMAC-signed tokens are only as strong as the shared secret",
                remediation="Use a strong, high-entropy signing secret (>=256 bits) or migrate to an asymmetric algorithm (RS256/ES256).",
                tool="webapp.jwt_analysis",
                references=["CWE-326"],
            ))

        exp = payload.get("exp")
        if exp is None:
            findings.append(Finding(
                title=f"JWT has no 'exp' (expiration) claim (source: {entry['source']})",
                severity="medium",
                confidence="high",
                affected_asset=url,
                evidence=f"Payload claims: {list(payload.keys())}",
                remediation="Always set a reasonable 'exp' claim; a token with no expiry is valid forever if leaked.",
                tool="webapp.jwt_analysis",
                references=["CWE-613"],
            ))
        else:
            try:
                if float(exp) < time.time():
                    findings.append(Finding(
                        title=f"JWT is expired but was still transmitted (source: {entry['source']})",
                        severity="low",
                        confidence="medium",
                        affected_asset=url,
                        evidence=f"exp={exp} is in the past",
                        remediation="Ensure expired tokens are not re-issued or cached in responses.",
                        tool="webapp.jwt_analysis",
                        references=["CWE-613"],
                    ))
            except (TypeError, ValueError):
                pass

        sensitive_claims = [k for k in payload if re.search(r"password|secret|ssn|credit|card", k, re.IGNORECASE)]
        if sensitive_claims:
            findings.append(Finding(
                title=f"JWT payload carries sensitive-looking claim(s): {', '.join(sensitive_claims)}",
                severity="high",
                confidence="medium",
                affected_asset=url,
                evidence="JWTs are base64-encoded, not encrypted — payload claims are trivially readable by anyone with the token.",
                remediation="Never place secrets/PII directly in JWT claims; store a reference and look it up server-side.",
                tool="webapp.jwt_analysis",
                references=["CWE-311"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"JWT analysis: {len(tokens)} token(s) discovered, {len(findings)} issue(s) found" if tokens \
        else "JWT analysis: no JWT-shaped token found in headers, cookies, or body"

    return tool_result(
        "webapp.jwt_analysis", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"tokens_found": len(tokens), "analyzed": analyzed},
    )


tool_registry.register("webapp.jwt_analysis", run, metadata={
    "name": "webapp.jwt_analysis",
    "domain": "webapp",
    "status": "completed",
    "description": "Passive JWT discovery in headers/cookies/body plus structural weakness analysis (alg=none, weak HMAC, missing exp)",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})
