#!/usr/bin/env python3
"""
NEXUS-STRIKE — red_team.credential_access_simulation
Domain: red_team
Safe, bounded simulation of MITRE ATT&CK Credential Access (TA0006).

T1110 (Brute Force) is exercised for real, but bounded and safe: if a login
form is discovered on the target via a real GET, this sends at most 2-3
deliberately-wrong authentication attempts (never real/guessed credentials,
never more than a handful of requests) purely to observe DETECTION SIGNAL —
account-lockout / rate-limiting behavior in the server's own responses. This
is not a brute-force attack; it is the smallest possible real probe that
still tells you whether an actual T1110 attempt would trip a control.

T1003 (OS Credential Dumping) cannot be exercised or observed via HTTP at
all — it is host-based — so it is reported as a simulated detection-signal
finding only, honestly labeled as such, following the same pattern as
purple_team.threat_simulation.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.red_team._ttp_common import resolve_target

_MAX_ATTEMPTS = 3
_LOGIN_PATHS = ("/", "/login", "/signin", "/admin", "/wp-login.php")
_FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
_LOGIN_MARKER_RE = re.compile(r'type=["\']?password|name=["\']?(pass(word)?|pwd)', re.IGNORECASE)

_T1003_HINT = (
    "T1003 (OS Credential Dumping) requires local host access — LSASS memory read "
    "(Sysmon Event 10, TargetImage=lsass.exe), SAM/SECURITY registry hive save "
    "(Event 4656/4663 on those hives), or a Mimikatz-family process/command-line "
    "signature. None of this is observable over the network, so it cannot be "
    "exercised or verified by this tool."
)


def _find_login_endpoint(target: str) -> tuple[str | None, str | None]:
    """Real, safe GET-only probe for a login form. Returns (post_url, note)."""
    base = target if "://" in target else f"http://{target}"
    for path in _LOGIN_PATHS:
        url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = safe_urlopen(req, timeout=5)
            body = resp.read(16384).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if _LOGIN_MARKER_RE.search(body):
            action_match = _FORM_ACTION_RE.search(body)
            post_url = urllib.parse.urljoin(url, action_match.group(1)) if action_match else url
            return post_url, f"Login form discovered at {url} (POST target: {post_url})"
    return None, None


def _bounded_wrong_credential_probe(post_url: str) -> tuple[list[dict], str]:
    """Send at most _MAX_ATTEMPTS deliberately-wrong auth attempts. Real, tiny, safe."""
    attempts: list[dict] = []
    for i in range(min(_MAX_ATTEMPTS, 3)):
        payload = urllib.parse.urlencode({
            "username": f"nexusstrike_probe_{i}",
            "password": f"NexusStrike-Deliberately-Wrong-{i}!",
            "user": f"nexusstrike_probe_{i}",
            "pass": f"NexusStrike-Deliberately-Wrong-{i}!",
        }).encode()
        try:
            req = urllib.request.Request(
                post_url, data=payload,
                headers={
                    "User-Agent": "NexusStrike/1.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            resp = safe_urlopen(req, timeout=5)
            attempts.append({"attempt": i + 1, "status": resp.status, "error": None})
        except urllib.error.HTTPError as exc:
            attempts.append({"attempt": i + 1, "status": exc.code, "error": None})
        except Exception as exc:
            attempts.append({"attempt": i + 1, "status": None, "error": str(exc)[:80]})
    statuses = [a["status"] for a in attempts if a["status"] is not None]
    lockout_signal = any(s in (403, 429, 503) for s in statuses)
    note = (
        f"{len(attempts)} deliberately-wrong auth attempts sent; response statuses={statuses}. "
        + ("Rate-limiting/lockout status code observed." if lockout_signal
           else "No rate-limiting/lockout status code observed in response codes alone "
                "(a real lockout may still be evaluated server-side without a distinct status).")
    )
    return attempts, note


def run(target: str, **kwargs: Any) -> dict:
    """Simulate MITRE ATT&CK Credential Access (TA0006) against a target.

    Parameters
    ----------
    target : str
        Target domain, IP, or URL.
    """
    findings: list[Finding] = []

    ip, dns_note = resolve_target(target)
    if ip is None:
        return tool_result(
            "red_team.credential_access_simulation", target,
            status=STATUS_FAILED,
            error=dns_note,
        )

    post_url, discovery_note = _find_login_endpoint(target)

    attempts_sent = 0
    if post_url:
        attempts, probe_note = _bounded_wrong_credential_probe(post_url)
        attempts_sent = len(attempts)
        findings.append(Finding(
            title="[OBSERVED] Credential Access: Brute Force (T1110) — bounded real auth probe",
            severity="medium" if not any(a["status"] in (403, 429, 503) for a in attempts) else "info",
            confidence="high",
            affected_asset=target,
            evidence=f"{discovery_note}. {probe_note}",
            remediation=(
                "Confirm account-lockout/rate-limiting policy triggers well before a real "
                "attacker's attempt budget, and that failed-auth volume alerts to the SOC "
                "(auth log 'failed login' spike detection)."
            ),
            tool="red_team.credential_access_simulation",
            references=["https://attack.mitre.org/techniques/T1110/"],
        ))
    else:
        findings.append(Finding(
            title="[OBSERVED] Credential Access: Brute Force (T1110) — no login endpoint discovered",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence=(
                f"No login form found at common paths ({', '.join(_LOGIN_PATHS)}) via a real "
                f"GET-only probe. {dns_note}. T1110 is not observable against this surface "
                "at scan time — no credential probe was sent."
            ),
            remediation="No unauthenticated login surface found; re-verify if the target changes.",
            tool="red_team.credential_access_simulation",
            references=["https://attack.mitre.org/techniques/T1110/"],
        ))

    findings.append(Finding(
        title="[SIMULATED — host-based, unobservable via network] Credential Access: OS Credential Dumping (T1003)",
        severity="info",
        confidence="tentative",
        affected_asset=target,
        evidence=_T1003_HINT,
        remediation=(
            "Validate T1003 detection coverage directly on endpoints (EDR LSASS-access "
            "protection, credential-guard) — this cannot be tested over the network."
        ),
        tool="red_team.credential_access_simulation",
        references=["https://attack.mitre.org/techniques/T1003/"],
    ))

    return tool_result(
        "red_team.credential_access_simulation", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=(
            f"Credential Access simulation complete: T1110 "
            f"{'exercised with a bounded real probe' if post_url else 'not observable (no login surface found)'}; "
            f"T1003 reported as simulated detection-signal only (host-based, not network-observable)."
        ),
        metadata={
            "dns_resolved_ip": ip,
            "login_endpoint_found": bool(post_url),
            "auth_attempts_sent": attempts_sent,
        },
    )


tool_registry.register("red_team.credential_access_simulation", run, metadata={
    "name": "red_team.credential_access_simulation",
    "domain": "red_team",
    "status": "completed",
    "description": (
        "Safe, bounded simulation of MITRE ATT&CK Credential Access (TA0006) — "
        "sends at most 3 deliberately-wrong auth attempts to a real discovered login "
        "endpoint to observe T1110 lockout/rate-limit detection signal; reports T1003 "
        "(host-based, not network-observable) as simulated detection-signal only."
    ),
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
