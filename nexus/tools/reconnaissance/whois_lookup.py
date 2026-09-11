#!/usr/bin/env python3
"""
NEXUS-STRIKE — reconnaissance tool: Whois Lookup
Domain: reconnaissance

A real WHOIS (RFC 3912) client — raw TCP to port 43, IANA-referral-following.
Previously this tool did zero WHOIS protocol work at all: despite the name,
it only ran DNS resolution and an HTTP/HTTPS GET, fully duplicating
dns_recon.py. Caught live during an end-to-end mission run this session.
"""
import ipaddress
import re
import socket

from nexus.tools.registry import tool_registry

_WHOIS_PORT = 43
_TIMEOUT = 8
_MAX_RESPONSE_BYTES = 32_768
_IANA_WHOIS = "whois.iana.org"
_ARIN_WHOIS = "whois.arin.net"

_REFERRAL_RE = re.compile(r"^\s*(?:refer|ReferralServer)\s*:\s*(?:whois://)?([A-Za-z0-9.\-]+)", re.MULTILINE | re.IGNORECASE)


def _query(server: str, query: str) -> str:
    with socket.create_connection((server, _WHOIS_PORT), timeout=_TIMEOUT) as sock:
        sock.sendall((query + "\r\n").encode("ascii", errors="ignore"))
        chunks = []
        total = 0
        while total < _MAX_RESPONSE_BYTES:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _whois(target: str) -> tuple[str, list[str]]:
    """Return (raw_response, servers_queried). Follows exactly one referral
    from the appropriate root registry (IANA for domains, ARIN for IPv4/v6),
    which is enough to reach the authoritative registrar/RIR for the vast
    majority of real-world lookups without an unbounded referral chain."""
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    root_server = _ARIN_WHOIS if is_ip else _IANA_WHOIS
    servers = [root_server]
    first_response = _query(root_server, target)

    match = _REFERRAL_RE.search(first_response)
    if not match:
        return first_response, servers
    referral_server = match.group(1)
    if referral_server.lower() == root_server.lower():
        return first_response, servers

    servers.append(referral_server)
    try:
        second_response = _query(referral_server, target)
        return f"{first_response}\n--- referred to {referral_server} ---\n{second_response}", servers
    except OSError:
        return first_response, servers


def run(target: str, **kwargs) -> dict:
    """reconnaissance tool: Whois Lookup"""
    findings = []
    try:
        raw, servers_queried = _whois(target)
        findings.append(f"Queried: {' -> '.join(servers_queried)}")

        if not raw.strip():
            findings.append("Empty WHOIS response (unassigned, private/reserved range, or no data)")
        else:
            interesting_fields = (
                "domain name", "registrar", "creation date", "registered", "updated date",
                "registry expiry", "expiration date", "name server", "netname", "orgname",
                "org-name", "country", "cidr", "netrange", "status",
            )
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("%") or stripped.startswith("#"):
                    continue
                if any(stripped.lower().startswith(field) for field in interesting_fields):
                    findings.append(stripped)
            if len(findings) == 1:  # only the "Queried:" line — nothing recognizable parsed
                findings.append(f"Raw response ({len(raw)} chars) had no recognizable WHOIS fields; "
                                 f"first line: {raw.strip().splitlines()[0][:150] if raw.strip() else ''}")
    except OSError as e:
        findings.append(f"WHOIS query failed: {e}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "reconnaissance.whois_lookup", "domain": "reconnaissance", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("reconnaissance.whois_lookup", run, metadata={
    "name": "reconnaissance.whois_lookup",
    "domain": "reconnaissance",
    "status": "completed",
    "description": "reconnaissance tool: real RFC 3912 WHOIS client (IANA/ARIN referral-following)",
    "parameters": {
        "target": "Target domain or IP address",
    },
})
