#!/usr/bin/env python3
"""
NEXUS-STRIKE — red_team.initial_access_simulation
Domain: red_team
Target-informed, safe simulation of MITRE ATT&CK Initial Access (TA0001)
techniques — genuinely inspects the target's real observable surface (a
single safe HTTP GET, no exploitation) and reports which Initial Access
techniques that surface actually exposes, plus the detection-relevant
signal a blue team should see if each technique were actually attempted.
Atomic-Red-Team-style safe emulation, following the same pattern as
purple_team.threat_simulation.
"""
from __future__ import annotations

import re
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

_LOGIN_MARKERS = re.compile(
    r"type=[\"']?password|name=[\"']?(pass(word)?|pwd)|<form[^>]*login",
    re.IGNORECASE,
)

# Techniques that CANNOT be observed by a safe, unauthenticated HTTP probe —
# reported as simulated detection-signal only, honestly labeled as such.
_UNOBSERVABLE_TECHNIQUES: list[tuple[str, str, str]] = [
    ("T1566.001", "Spearphishing Attachment",
     "Email gateway/EDR sandbox detonation alert on malicious attachment; Sysmon Event 1 for Office spawning cmd.exe/powershell.exe"),
    ("T1566.002", "Spearphishing Link",
     "Secure email gateway URL-rewrite click telemetry; proxy log entry for user click-through to a newly-registered domain"),
    ("T1200", "Hardware Additions",
     "Endpoint USB/PnP device-insertion alert (Windows Event 20001/DeviceSetupManager) for an unrecognized device class"),
]


def run(target: str, simulate_detection: bool = True, seed: int | None = None, **kwargs: Any) -> dict:
    """Simulate MITRE ATT&CK Initial Access (TA0001) against a target.

    Parameters
    ----------
    target : str
        Target domain, IP, or URL.
    simulate_detection : bool
        Probabilistically simulate detection outcomes for the techniques
        that cannot be verified by direct observation (default: True).
    seed : int, optional
        Random seed for reproducible simulation results.
    """
    findings: list[Finding] = []

    ip, dns_note = resolve_target(target)
    if ip is None:
        return tool_result(
            "red_team.initial_access_simulation", target,
            status=STATUS_FAILED,
            error=dns_note,
        )

    # ── Real, safe observation of the actual attack surface ────────────────
    host = target if "://" in target else f"http://{target}/"
    status_code: int | None = None
    server_header = "unknown"
    body_sample = ""
    try:
        req = urllib.request.Request(host, headers={"User-Agent": "NexusStrike/1.0"})
        resp = safe_urlopen(req, timeout=5)
        status_code = resp.status
        server_header = resp.headers.get("Server", "unknown")
        try:
            body_sample = resp.read(8192).decode("utf-8", errors="ignore")
        except Exception:
            body_sample = ""
        http_reachable = True
        http_error = ""
    except Exception as exc:
        http_reachable = False
        http_error = str(exc)[:120]

    # T1190 — Exploit Public-Facing Application: this is a REAL observation,
    # not a simulation — the app IS or ISN'T reachable and fingerprintable.
    if http_reachable:
        findings.append(Finding(
            title="[OBSERVED] Initial Access: Exploit Public-Facing Application (T1190)",
            severity="info",
            confidence="certain",
            affected_asset=target,
            evidence=(
                f"Real HTTP probe: {host} responded {status_code} "
                f"(Server={server_header}). {dns_note}. This is the real, "
                f"reachable public-facing surface a T1190 attempt would target."
            ),
            remediation=(
                "Ensure WAF/IDS coverage in front of this application and that exploit "
                "signature alerts route to the SOC. Confirm patch level for the fingerprinted "
                "server software."
            ),
            tool="red_team.initial_access_simulation",
            references=["https://attack.mitre.org/techniques/T1190/"],
        ))

        login_form_present = bool(_LOGIN_MARKERS.search(body_sample))
        if login_form_present:
            # T1078 — Valid Accounts: real observation that credential-based
            # initial access is a live avenue here (there IS an auth surface).
            findings.append(Finding(
                title="[OBSERVED] Initial Access: Valid Accounts (T1078) — authentication surface exposed",
                severity="medium",
                confidence="high",
                affected_asset=target,
                evidence=(
                    f"Response body from {host} contains a login/password form marker. "
                    "A real T1078 attempt (credential stuffing/reuse) against this endpoint "
                    "would authenticate normally and evade exploit-signature detection."
                ),
                remediation=(
                    "Verify authentication-anomaly alerting is active for this endpoint "
                    "(off-hours logins, impossible travel, credential-stuffing rate spikes). "
                    "Enforce MFA."
                ),
                tool="red_team.initial_access_simulation",
                references=["https://attack.mitre.org/techniques/T1078/"],
            ))
    else:
        findings.append(Finding(
            title="[OBSERVED] Initial Access: Exploit Public-Facing Application (T1190) — surface not reachable",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence=f"Real HTTP probe to {host} failed: {http_error}. No public HTTP(S) surface observed for T1190.",
            remediation="No web-facing surface found on this vector at scan time; re-verify if this changes.",
            tool="red_team.initial_access_simulation",
            references=["https://attack.mitre.org/techniques/T1190/"],
        ))

    # ── Techniques a safe unauthenticated HTTP probe genuinely cannot verify ─
    findings.extend([
        Finding(
            title=f"[SIMULATED — unobservable via network recon] Initial Access: {name} ({tid})",
            severity="info",
            confidence="tentative",
            affected_asset=target,
            evidence=(
                f"{tid} ({name}) cannot be exercised or verified by a safe, unauthenticated "
                f"network probe — it requires a user-facing delivery vector (email/physical) "
                f"this tool does not send. Expected detection signal if it occurred: {hint}"
            ),
            remediation=(
                f"Validate {tid} coverage through your email-security/EDR pipeline directly "
                f"(e.g., a controlled phishing simulation platform), not through network recon."
            ),
            tool="red_team.initial_access_simulation",
            references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
        )
        for tid, name, hint in _UNOBSERVABLE_TECHNIQUES
    ])

    observed = sum(1 for f in findings if "[OBSERVED]" in f.title)
    simulated = sum(1 for f in findings if "[SIMULATED" in f.title)

    return tool_result(
        "red_team.initial_access_simulation", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=(
            f"Initial Access simulation complete: {observed} technique(s) evaluated against the "
            f"real observed surface, {simulated} technique(s) reported as simulated detection-signal "
            f"only (not verifiable via safe network recon)."
        ),
        metadata={
            "dns_resolved_ip": ip,
            "http_reachable": http_reachable,
            "http_status": status_code,
            "server_header": server_header,
            "observed_techniques": observed,
            "simulated_techniques": simulated,
        },
    )


tool_registry.register("red_team.initial_access_simulation", run, metadata={
    "name": "red_team.initial_access_simulation",
    "domain": "red_team",
    "status": "completed",
    "description": (
        "Target-informed safe simulation of MITRE ATT&CK Initial Access (TA0001) — "
        "real HTTP recon of the target's actual attack surface (T1190/T1078), plus "
        "simulated detection-signal reporting for techniques a safe network probe "
        "cannot exercise (T1566 phishing, T1200 hardware additions)."
    ),
    "parameters": {
        "target": "Target domain, IP, or URL",
        "simulate_detection": "Model detection outcomes for unobservable techniques (default: True)",
        "seed": "Random seed for reproducible simulation results (optional)",
    },
})
