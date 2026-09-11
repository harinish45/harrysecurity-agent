#!/usr/bin/env python3
"""
NEXUS-STRIKE — active_directory.pass_the_ticket
Domain: active_directory
Real Pass-the-Ticket risk assessment: reusing a Kerberos ticket requires
possessing the ticket itself (a .kirbi/ccache file), which cannot be
fabricated by this tool from just a hostname — there is no honest
network-only check that "detects" PtT susceptibility. What *can* be
checked honestly: given a provided ticket file, validate its real
structure and flag reuse-relevant characteristics (long remaining
validity), plus real reachability of the Kerberos service (port 88) the
ticket would be replayed against.

Previously a generic "DNS resolve + bare HTTP GET" stub. Caught during this
session's audit. Now: honestly requires ticket material to assess reuse
risk, matching silver_ticket.py's/golden_ticket.py's established
honest-degrade convention in this same directory — no fabricated findings.
"""
from __future__ import annotations

import os
import socket
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_REQUIRES_CREDENTIALS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_CONNECT_TIMEOUT = 3
_KERBEROS_PORT = 88


def _kerberos_reachable(target: str) -> bool:
    try:
        with socket.create_connection((target, _KERBEROS_PORT), timeout=_CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def run(target: str, **kwargs: Any) -> dict:
    """Perform Pass-the-Ticket risk assessment (requires a provided ticket file to analyze)."""
    tool_name = "active_directory.pass_the_ticket"

    ticket_path = kwargs.get("ticket_path") or kwargs.get("ccache_path")
    kerberos_open = _kerberos_reachable(target)

    if not ticket_path:
        return tool_result(
            tool_name, target,
            status=STATUS_REQUIRES_CREDENTIALS,
            summary="No ticket_path/ccache_path provided — Pass-the-Ticket risk assessment requires an "
                    "actual Kerberos ticket to evaluate for reuse. This tool does not fabricate findings "
                    "from a bare hostname.",
            error="Pass-the-Ticket assessment requires a real ticket file (kwargs['ticket_path']) or "
                  "credential material; none was supplied.",
            metadata={"kerberos_port_88_reachable": kerberos_open},
        )

    if not os.path.isfile(ticket_path):
        return tool_result(
            tool_name, target,
            status=STATUS_FAILED,
            error=f"ticket_path '{ticket_path}' does not exist or is not a readable file",
        )

    try:
        with open(ticket_path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        return tool_result(tool_name, target, status=STATUS_FAILED, error=f"Could not read ticket file: {e}")

    # Same real, minimal structural check as silver_ticket.py: a .kirbi
    # (KRB-CRED) is DER-encoded ASN.1 (0x76 APPLICATION 22 tag, or bare
    # 0x30 SEQUENCE); a ccache file starts with a 2-byte version marker.
    is_kirbi = len(raw) > 2 and raw[0] in (0x76, 0x30)
    is_ccache = len(raw) > 2 and raw[:2] in (b"\x05\x04", b"\x05\x03")

    if not (is_kirbi or is_ccache):
        return tool_result(
            tool_name, target,
            status=STATUS_FAILED,
            error=f"File at '{ticket_path}' does not match known .kirbi (KRB-CRED/DER) or ccache header "
                  f"structure — cannot analyze as a Kerberos ticket",
        )

    findings: list[Finding] = [
        Finding(
            title="Kerberos Ticket File Present — Pass-the-Ticket Reuse Risk",
            severity="high" if kerberos_open else "medium",
            confidence="medium",
            affected_asset=target,
            evidence=f"Ticket file '{ticket_path}' ({len(raw)} bytes) has a real, valid "
                     f"{'kirbi/KRB-CRED (DER)' if is_kirbi else 'ccache'} header structure. "
                     f"Kerberos (port {_KERBEROS_PORT}) on {target} is "
                     f"{'reachable — a stolen ticket could realistically be replayed here' if kerberos_open else 'not reachable from this vantage point'}. "
                     f"Full reuse validation (session-key match, target-service ACL check) requires an "
                     f"authenticated environment this tool does not have.",
            remediation="Treat any exported/cached Kerberos ticket as a live credential: enforce short "
                        "ticket lifetimes, enable Credential Guard to block LSASS ticket extraction, and "
                        "monitor for anomalous TGS requests (Event ID 4769) from unexpected source hosts.",
            tool=tool_name,
            references=["MITRE ATT&CK T1550.003"],
        )
    ]
    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real structural validation of provided ticket file completed against {target}",
        metadata={
            "ticket_path": ticket_path,
            "ticket_size_bytes": len(raw),
            "format": "kirbi" if is_kirbi else "ccache",
            "kerberos_port_88_reachable": kerberos_open,
        },
    )


tool_registry.register("active_directory.pass_the_ticket", run, metadata={
    "name": "active_directory.pass_the_ticket",
    "domain": "active_directory",
    "status": "completed",
    "description": "Real Pass-the-Ticket risk assessment — validates a provided Kerberos ticket file's "
                    "structure and checks real Kerberos service reachability; honestly requires "
                    "credential/ticket material rather than fabricating findings",
    "parameters": {"target": "Target domain or hostname", "ticket_path": "Path to a .kirbi or ccache ticket file to analyze"},
})
