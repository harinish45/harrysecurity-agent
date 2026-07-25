#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance.dns_recon
Domain: reconnaissance
DNS reconnaissance with record enumeration, zone transfer attempts, and DNS security checks.
"""
from __future__ import annotations

import ipaddress
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

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR", "NAPTR"]


def _get_dns_records(hostname: str, record_type: str, timeout: float = 5.0) -> Optional[list[str]]:
    """Query DNS records for a hostname. Returns None if dnspython unavailable."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(hostname, record_type, raise_on_no_answer=False)
        return [str(rdata) for rdata in answers]
    except ImportError:
        return None
    except Exception:
        return []


def _attempt_zone_transfer(domain: str, timeout: float = 5.0) -> tuple[bool, list[str]]:
    """Attempt DNS zone transfer (AXFR) for full zone enumeration."""
    try:
        import dns.resolver
        import dns.zone
        import dns.query
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        ns_records = resolver.resolve(domain, "NS", raise_on_no_answer=False)
        names = [str(rdata) for rdata in ns_records]
        if not names:
            return False, []

        zone_records = []
        for ns in names:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=timeout))
                if zone:
                    for name in zone.nodes:
                        zone_records.append(str(name))
                    return True, zone_records[:100]
            except Exception:
                continue
        return False, []
    except Exception:
        return False, []


def _check_dns_security(domain: str) -> dict:
    """Check DNS security configurations (DNSSEC, CAA, etc.)."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        security_info = {}
        try:
            ds_records = resolver.resolve(domain, "DS", raise_on_no_answer=False)
            security_info["dnssec"] = bool(ds_records)
        except Exception:
            security_info["dnssec"] = False

        try:
            caa_records = resolver.resolve(domain, "CAA", raise_on_no_answer=False)
            security_info["caa"] = [str(rdata) for rdata in caa_records]
        except Exception:
            security_info["caa"] = []

        try:
            txt_records = resolver.resolve(domain, "TXT", raise_on_no_answer=False)
            for txt in txt_records:
                txt_str = str(txt)
                if "spf" in txt_str.lower():
                    security_info["spf"] = txt_str
                if "dmarc" in txt_str.lower():
                    security_info["dmarc"] = txt_str
                if "dkim" in txt_str.lower():
                    security_info["dkim"] = txt_str
        except Exception:
            pass

        return security_info
    except ImportError:
        return {"dnssec": False, "caa": [], "spf": None, "dmarc": None, "dkim": None}
    except Exception:
        return {"dnssec": False, "caa": [], "spf": None, "dmarc": None, "dkim": None}


def run(
    target: str,
    record_types: list[str] | None = None,
    zone_transfer: bool = False,
    check_security: bool = True,
    timeout: float = 5.0,
    **kwargs: Any,
) -> dict:
    """Perform DNS reconnaissance against a domain.

    Parameters
    ----------
    target : str
        Domain name to enumerate DNS records for.
    record_types : list[str], optional
        DNS record types to query. Defaults to all common types.
    zone_transfer : bool
        Attempt DNS zone transfer (AXFR) for full zone enumeration.
    check_security : bool
        Check DNS security configurations (DNSSEC, CAA, SPF, DMARC).
    timeout : float
        Query timeout in seconds.
    """
    domain = target.strip().lower()
    if not domain:
        return tool_result("reconnaissance.dns_recon", target, status=STATUS_FAILED, error="Empty target")

    if "." not in domain or domain.startswith("."):
        return tool_result("reconnaissance.dns_recon", target, status=STATUS_FAILED, error=f"Invalid domain: {domain}")

    findings: list[Finding] = []
    records_found: dict[str, list[str]] = {}

    records_to_check = record_types or DNS_RECORD_TYPES

    for rtype in records_to_check:
        records = _get_dns_records(domain, rtype, timeout)
        if records is None:
            return tool_result(
                "reconnaissance.dns_recon", target,
                status=STATUS_UNAVAILABLE,
                error="dnspython library not installed (pip install dnspython)",
            )
        if records:
            records_found[rtype] = records
            for record in records[:10]:
                findings.append(Finding(
                    title=f"{rtype} record for {domain}",
                    severity="info",
                    confidence="certain",
                    affected_asset=domain,
                    evidence=f"{rtype}: {record}",
                    remediation="Verify DNS record is intentional and properly configured.",
                    tool="reconnaissance.dns_recon",
                    references=["CWE-200"],
                ))

    zone_found = False
    if zone_transfer:
        zone_found, zone_records = _attempt_zone_transfer(domain, timeout)
        if zone_found and zone_records:
            findings.append(Finding(
                title=f"DNS zone transfer successful for {domain}",
                severity="high",
                confidence="certain",
                affected_asset=domain,
                evidence=f"Zone contains {len(zone_records)} records: {zone_records[:20]}",
                remediation="DNS zone transfer should be restricted to authorized nameservers only.",
                tool="reconnaissance.dns_recon",
                references=["CWE-200", "CWE-284"],
            ))

    if check_security:
        security = _check_dns_security(domain)
        if security.get("dnssec") is False:
            findings.append(Finding(
                title=f"{domain} has no DNSSEC",
                severity="low",
                confidence="high",
                affected_asset=domain,
                evidence="Domain does not have DNSSEC enabled",
                remediation="Consider enabling DNSSEC for cryptographic authentication of DNS responses.",
                tool="reconnaissance.dns_recon",
                references=["CWE-354"],
            ))
        if not security.get("caa"):
            findings.append(Finding(
                title=f"{domain} has no CAA records",
                severity="low",
                confidence="high",
                affected_asset=domain,
                evidence="Domain does not have Certificate Authority Authorization records",
                remediation="Add CAA records to restrict which CAs may issue certificates.",
                tool="reconnaissance.dns_recon",
                references=["CWE-354"],
            ))
        if security.get("spf"):
            findings.append(Finding(
                title=f"{domain} SPF record found",
                severity="info",
                confidence="certain",
                affected_asset=domain,
                evidence=f"SPF: {security['spf'][:200]}",
                remediation="Verify SPF record is correct to prevent email spoofing.",
                tool="reconnaissance.dns_recon",
                references=["CWE-354"],
            ))

    if records_found or zone_found:
        total_records = sum(len(v) for v in records_found.values())
        return tool_result(
            "reconnaissance.dns_recon", target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Found {total_records} DNS records for {domain} across {len(records_found)} types",
            metadata={"records_found": records_found, "zone_transfer": zone_found},
        )

    return tool_result(
        "reconnaissance.dns_recon", target,
        status=STATUS_NO_FINDINGS,
        summary=f"No DNS records found for {domain}",
        metadata={"records_found": {}, "zone_transfer": zone_found},
    )


tool_registry.register("reconnaissance.dns_recon", run, metadata={
    "name": "reconnaissance.dns_recon",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "DNS reconnaissance with record enumeration and security checks",
    "parameters": {
        "target": "Target domain to enumerate DNS records",
        "record_types": "DNS record types to query (default: A,AAAA,MX,NS,TXT,SOA,CNAME,SRV,CAA,PTR,NAPTR)",
        "zone_transfer": "Attempt DNS zone transfer for full zone enumeration",
        "check_security": "Check DNSSEC, CAA, SPF, DMARC (default: True)",
        "timeout": "Query timeout in seconds (default: 5s)",
    },
})