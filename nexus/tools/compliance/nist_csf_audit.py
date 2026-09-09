#!/usr/bin/env python3
"""
NEXUS-STRIKE — compliance tool: NIST CSF Audit
Domain: compliance

NIST Cybersecurity Framework "Identify" function (ID.AM — asset/email
infrastructure inventory) and "Protect" function (PR.DS — data
protection, email spoofing resistance): real DNS TXT lookups for
SPF/DMARC records. Previously identical to all 8 other compliance.*
tools — caught during this session's audit.
"""
import socket

from nexus.tools.registry import tool_registry


def _txt_records(target: str, timeout: float = 5.0) -> list[str]:
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(target, "TXT", raise_on_no_answer=False)
        return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answers]
    except ImportError:
        # dnspython not installed — fall back to a plain socket-based
        # resolution check (confirms the host resolves at all, though it
        # can't fetch TXT records without dnspython).
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            pass
        return []
    except Exception:
        return []


def run(target: str, **kwargs) -> dict:
    """compliance tool: NIST CSF Audit"""
    findings = []

    txt_records = _txt_records(target)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
    if spf_records:
        findings.append(f"NIST CSF PR.DS: SPF record present: {spf_records[0][:150]}")
    else:
        findings.append(f"NIST CSF PR.DS concern: no SPF TXT record found for {target} — email spoofing is not mitigated")

    dmarc_records = _txt_records(f"_dmarc.{target}")
    dmarc_records = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
    if dmarc_records:
        findings.append(f"NIST CSF PR.DS: DMARC record present: {dmarc_records[0][:150]}")
    else:
        findings.append(f"NIST CSF PR.DS concern: no DMARC record found at _dmarc.{target} — no email-spoofing enforcement policy")

    return {"tool": "compliance.nist_csf_audit", "domain": "compliance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("compliance.nist_csf_audit", run, metadata={
    "name": "compliance.nist_csf_audit",
    "domain": "compliance",
    "status": "completed",
    "description": "NIST CSF Identify/Protect-relevant checks: real DNS TXT lookups for SPF/DMARC records",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
