#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.email_harvest
Domain: reconnaissance

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to email harvesting).
Caught during a follow-up audit. Now performs real, passive DNS-based
reconnaissance only — real MX record lookup and real SPF/DMARC TXT record
retrieval — plus generates a real, clearly-labeled set of common
email-address permutations for a supplied employee name, if one is given.
No active scraping of third-party sites (which would violate ToS and is
unreliable) is performed.
"""
from __future__ import annotations

import socket
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "reconnaissance.email_harvest"

_COMMON_PATTERNS = [
    "{first}.{last}", "{first}{last}", "{f}{last}", "{first}",
    "{last}.{first}", "{f}.{last}", "{first}_{last}",
]


def _mx_records(domain: str) -> list[str]:
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        return sorted(str(a.exchange).rstrip(".") for a in answers)
    except ImportError:
        pass
    except Exception:
        return []
    # Fallback: no dnspython — socket has no MX support, so this path is
    # honestly limited to confirming the domain resolves at all.
    return []


def _txt_records_via_dnspython(domain: str) -> list[str]:
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except Exception:
        return []


def _generate_patterns(first: str, last: str, domain: str) -> list[str]:
    first, last = first.lower().strip(), last.lower().strip()
    f = first[:1]
    out = []
    for pattern in _COMMON_PATTERNS:
        local = pattern.format(first=first, last=last, f=f)
        if local:
            out.append(f"{local}@{domain}")
    return out


def run(target: str, **kwargs: Any) -> dict:
    """Real passive DNS-based email-infrastructure recon (MX/SPF/DMARC) plus optional pattern generation."""
    domain = target.strip().lower()
    if not domain:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error="Empty target")

    try:
        socket.gethostbyname(domain)
    except socket.gaierror as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"DNS resolution failed: {e}")

    findings: list[Finding] = []
    mx_hosts = _mx_records(domain)
    if mx_hosts:
        findings.append(Finding(
            title=f"Mail infrastructure discovered for {domain}",
            severity="info",
            confidence="certain",
            affected_asset=domain,
            evidence=f"Real MX record lookup returned: {mx_hosts}",
            remediation="Confirm all MX records point to expected, currently-operated mail infrastructure.",
            tool=_TOOL_NAME,
            references=["CWE-200"],
        ))

    txt_records = _txt_records_via_dnspython(domain)
    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    dmarc = _txt_records_via_dnspython(f"_dmarc.{domain}")
    dmarc_record = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)

    if spf:
        findings.append(Finding(
            title=f"SPF record present for {domain}",
            severity="info", confidence="certain", affected_asset=domain,
            evidence=f"Real DNS TXT lookup: {spf}",
            remediation="Verify SPF policy is 'hard fail' (-all) rather than 'soft fail' (~all) for anti-spoofing.",
            tool=_TOOL_NAME, references=["CWE-290"],
        ))
    else:
        findings.append(Finding(
            title=f"No SPF record found for {domain}",
            severity="medium", confidence="high", affected_asset=domain,
            evidence="Real DNS TXT lookup for an SPF record (v=spf1...) returned none",
            remediation="Publish an SPF record to reduce the risk of email spoofing against this domain.",
            tool=_TOOL_NAME, references=["CWE-290"],
        ))

    if dmarc_record:
        findings.append(Finding(
            title=f"DMARC record present for {domain}",
            severity="info", confidence="certain", affected_asset=domain,
            evidence=f"Real DNS TXT lookup on _dmarc.{domain}: {dmarc_record}",
            remediation="Verify DMARC policy is 'reject' or 'quarantine', not 'none', for effective anti-spoofing.",
            tool=_TOOL_NAME, references=["CWE-290"],
        ))
    else:
        findings.append(Finding(
            title=f"No DMARC record found for {domain}",
            severity="medium", confidence="high", affected_asset=domain,
            evidence=f"Real DNS TXT lookup on _dmarc.{domain} returned no DMARC policy record",
            remediation="Publish a DMARC policy to reduce the risk of email spoofing against this domain.",
            tool=_TOOL_NAME, references=["CWE-290"],
        ))

    employee_name = kwargs.get("employee_name")
    generated_patterns: list[str] = []
    if employee_name and " " in employee_name.strip():
        first, _, last = employee_name.strip().partition(" ")
        generated_patterns = _generate_patterns(first, last, domain)
        findings.append(Finding(
            title=f"Generated candidate email addresses for '{employee_name}' at {domain}",
            severity="info", confidence="low", affected_asset=domain,
            evidence=f"Common naming-convention permutations (not verified to exist): {generated_patterns}",
            remediation="These are unverified pattern-based guesses for social-engineering-awareness "
                        "training purposes only, not confirmed real addresses.",
            tool=_TOOL_NAME, references=["MITRE ATT&CK T1589.002"],
        ))

    if not findings:
        return tool_result(_TOOL_NAME, target, status=STATUS_NO_FINDINGS, summary=f"No email-infrastructure signals found for {domain}")

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Email-infrastructure recon for {domain}: {len(mx_hosts)} MX host(s), "
                f"SPF={'present' if spf else 'missing'}, DMARC={'present' if dmarc_record else 'missing'}",
        metadata={"mx_hosts": mx_hosts, "spf_present": bool(spf), "dmarc_present": bool(dmarc_record),
                  "generated_email_patterns": generated_patterns},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "reconnaissance",
    "status": "completed",
    "description": "Real passive DNS-based email-infrastructure recon (MX/SPF/DMARC records); optionally "
                    "generates unverified candidate email-address patterns for a supplied employee name",
    "parameters": {
        "target": "Target domain",
        "employee_name": "(optional) 'First Last' name to generate candidate email address patterns for",
    },
})
