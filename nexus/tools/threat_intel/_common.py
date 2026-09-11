"""Shared real-lookup helpers for the threat_intel IOC tools (threat_feeds,
ioc_enrichment, ti_ioc_collection).

These three tools legitimately share the same underlying real network
logic — a free, no-key Spamhaus ZEN DNSBL reputation lookup for IP
indicators, and an API-key-gated VirusTotal/OTX lookup for domain/hash
indicators — while each still produces its own tool-specific finding
framing (feed correlation vs. single-indicator enrichment vs. IOC
collection record). This is the honest kind of code reuse: one real
implementation, imported three times. It replaces what an audit this
session found to be three (of eight) *fake* threat_intel stubs sharing
byte-for-byte-identical logic that did nothing real (a DNS resolve + a
bare HTTP GET on `/`, unrelated to threat intelligence).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen

_SPAMHAUS_ZEN = "zen.spamhaus.org"

# https://www.spamhaus.org/zen/ return-code reference (the codes Spamhaus
# ZEN actually resolves listed IPs to).
_SPAMHAUS_RETURN_CODES = {
    "127.0.0.2": "Spamhaus SBL — spam source",
    "127.0.0.3": "Spamhaus SBL CSS — spam source (snowshoe)",
    "127.0.0.4": "Spamhaus XBL — exploited/compromised host",
    "127.0.0.9": "Spamhaus SBL DROP/EDROP — hijacked/malicious netblock",
    "127.0.0.10": "Spamhaus PBL — ISP policy block (dynamic range)",
    "127.0.0.11": "Spamhaus PBL — policy block (spam-support)",
}

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def classify_target(target: str) -> str:
    """Return 'ip', 'hash', or 'domain' for the given IOC string."""
    t = (target or "").strip()
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if _MD5_RE.match(t) or _SHA1_RE.match(t) or _SHA256_RE.match(t):
        return "hash"
    return "domain"


def dnsbl_lookup(ip: str, zone: str = _SPAMHAUS_ZEN) -> dict[str, Any]:
    """Real Spamhaus ZEN DNSBL lookup.

    Reverses the IPv4 octets and resolves ``<reversed-ip>.zen.spamhaus.org``
    via a genuine DNS query (``socket.gethostbyname``) — a resolvable A
    record means the IP is listed on one of Spamhaus's blocklists; NXDOMAIN
    (``socket.gaierror``) means it is not. No API key required, no
    fabricated data — either a real DNS answer came back or it didn't.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"queried": False, "listed": False, "error": f"{ip!r} is not a valid IP address"}
    if addr.version != 4:
        return {"queried": False, "listed": False, "error": "Spamhaus ZEN DNSBL only supports IPv4 lookups"}

    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.{zone}"
    try:
        result_ip = socket.gethostbyname(query)
        return {
            "queried": True,
            "listed": True,
            "query": query,
            "return_code": result_ip,
            "reason": _SPAMHAUS_RETURN_CODES.get(result_ip, f"Listed (return code {result_ip})"),
        }
    except socket.gaierror:
        return {"queried": True, "listed": False, "query": query}
    except OSError as exc:
        return {"queried": False, "listed": False, "error": f"DNSBL lookup failed: {exc}"}


def get_api_key(*names: str) -> tuple[str, str] | None:
    """Return (env_var_name, key_value) for the first of `names` set in the
    environment, else None. Deliberately reads only ``os.environ`` — this
    codebase does not auto-load `.env` into the process environment, so a
    key present only in a `.env` file (not actually exported) honestly
    reads as absent here rather than being silently picked up."""
    for name in names:
        value = os.getenv(name)
        if value:
            return name, value
    return None


def query_virustotal(indicator: str, kind: str, api_key: str, timeout: float = 15.0) -> dict:
    """Real VirusTotal v3 API lookup for a domain or file hash."""
    path = "domains" if kind == "domain" else "files"
    url = f"https://www.virustotal.com/api/v3/{path}/{urllib.parse.quote(indicator, safe='')}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key, "User-Agent": "NexusStrike/1.0"})
    with safe_urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def query_otx(indicator: str, kind: str, api_key: str, timeout: float = 15.0) -> dict:
    """Real AlienVault OTX API lookup for a domain or file hash."""
    section = "domain" if kind == "domain" else "file"
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{urllib.parse.quote(indicator, safe='')}/general"
    req = urllib.request.Request(url, headers={"X-OTX-API-KEY": api_key, "User-Agent": "NexusStrike/1.0"})
    with safe_urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


class FeedHTTPError(Exception):
    """Wraps urllib.error.HTTPError with the info callers need without
    forcing every call site to import urllib.error itself."""

    def __init__(self, code: int, reason: str):
        self.code = code
        self.reason = reason
        super().__init__(f"HTTP {code}: {reason}")


def query_keyed_feed(indicator: str, kind: str, key_info: tuple[str, str]) -> tuple[str, dict]:
    """Dispatch to VirusTotal or OTX based on which env var supplied the
    key, and normalise HTTPError into FeedHTTPError so callers get a plain
    exception hierarchy to handle."""
    env_name, api_key = key_info
    try:
        if env_name == "VIRUSTOTAL_API_KEY":
            return "VirusTotal", query_virustotal(indicator, kind, api_key)
        return "OTX", query_otx(indicator, kind, api_key)
    except urllib.error.HTTPError as exc:
        raise FeedHTTPError(exc.code, str(exc.reason)) from exc
