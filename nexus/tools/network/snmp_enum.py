#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.snmp_enum
Domain: network

Previously a plain generic port sweep (byte-for-byte identical to
nfs_enum.py, smb_enum.py, etc. before this fix) — it never spoke SNMP at
all, and never even probed UDP/161 (the sweep was TCP-only). Caught during
this session's audit.

Now: a real, hand-built BER/ASN.1-encoded SNMPv1/v2c GET request for
sysDescr.0 (1.3.6.1.2.1.1.1.0) using the well-known "public" community
string over UDP/161 — the standard, safe way to check for the classic
"SNMP exposed with default community" misconfiguration (the same check
`snmpget -v2c -c public <host> sysDescr.0` performs). No external SNMP
library is required or available in this environment (pysnmp is not in
requirements.txt), so the BER encoding/decoding is done directly.
"""
from __future__ import annotations

import socket
import struct
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_SNMP_PORT = 161
_SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)


# ── Minimal BER/ASN.1 encoder (just enough for an SNMP GetRequest) ──────────

def _ber_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    encoded = []
    while n:
        encoded.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(encoded)]) + bytes(encoded)


def _ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(content)) + content


def _ber_integer(value: int) -> bytes:
    if value == 0:
        content = b"\x00"
    else:
        content = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return _ber_tlv(0x02, content)


def _ber_octet_string(value: bytes) -> bytes:
    return _ber_tlv(0x04, value)


def _ber_null() -> bytes:
    return _ber_tlv(0x05, b"")


def _ber_oid(nodes: tuple[int, ...]) -> bytes:
    first = nodes[0] * 40 + nodes[1]
    out = bytearray([first])
    for node in nodes[2:]:
        if node < 0x80:
            out.append(node)
        else:
            chunk = []
            n = node
            while n:
                chunk.insert(0, n & 0x7F)
                n >>= 7
            for i, b in enumerate(chunk):
                out.append(b | 0x80 if i < len(chunk) - 1 else b)
    return _ber_tlv(0x06, bytes(out))


def _build_snmp_get_request(community: bytes = b"public", version: int = 1, request_id: int = 0x4E455853) -> bytes:
    """version=1 means SNMPv2c per the SNMP version encoding (0=v1,1=v2c)."""
    varbind = _ber_tlv(0x30, _ber_oid(_SYSDESCR_OID) + _ber_null())
    varbind_list = _ber_tlv(0x30, varbind)
    pdu_body = _ber_integer(request_id) + _ber_integer(0) + _ber_integer(0) + varbind_list
    pdu = _ber_tlv(0xA0, pdu_body)  # 0xA0 = GetRequest-PDU
    message = _ber_integer(version) + _ber_octet_string(community) + pdu
    return _ber_tlv(0x30, message)


# ── Minimal BER decoder (just enough to pull the sysDescr value back out) ──

def _parse_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte & 0x80:
        num_len_bytes = length_byte & 0x7F
        length = int.from_bytes(data[offset + 2:offset + 2 + num_len_bytes], "big")
        value_start = offset + 2 + num_len_bytes
    else:
        length = length_byte
        value_start = offset + 2
    value = data[value_start:value_start + length]
    return tag, value, value_start + length


def _extract_sysdescr(response: bytes) -> str | None:
    try:
        _, message, _ = _parse_tlv(response, 0)
        pos = 0
        _, _, pos = _parse_tlv(message, pos)          # version
        _, _, pos = _parse_tlv(message, pos)          # community
        pdu_tag, pdu_body, _ = _parse_tlv(message, pos)  # PDU (GetResponse = 0xA2)
        p = 0
        _, _, p = _parse_tlv(pdu_body, p)              # request-id
        _, err_status, p = _parse_tlv(pdu_body, p)      # error-status
        _, _, p = _parse_tlv(pdu_body, p)              # error-index
        _, vbl, _ = _parse_tlv(pdu_body, p)             # varbind list SEQUENCE
        _, vb, _ = _parse_tlv(vbl, 0)                   # first varbind SEQUENCE
        p2 = 0
        _, _, p2 = _parse_tlv(vb, p2)                   # OID
        val_tag, val, _ = _parse_tlv(vb, p2)             # value
        if val_tag == 0x04:  # OCTET STRING
            return val.decode("utf-8", errors="replace")
        return f"<non-string value, BER tag=0x{val_tag:02x}: {val[:64].hex()}>"
    except (IndexError, ValueError):
        return None


def _snmp_get(target: str, community: str, timeout: float) -> dict:
    result: dict[str, Any] = {"responded": False, "community": community}
    request = _build_snmp_get_request(community.encode())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(request, (target, _SNMP_PORT))
        data, _ = sock.recvfrom(4096)
        result["responded"] = True
        result["raw_response_hex"] = data[:64].hex()
        sysdescr = _extract_sysdescr(data)
        if sysdescr is not None:
            result["sysdescr"] = sysdescr
    except (socket.timeout, OSError) as e:
        result["error"] = str(e)[:120]
    finally:
        sock.close()
    return result


def run(target: str, community: str = "public", timeout: float = 3.0, **kwargs: Any) -> dict:
    """Real SNMPv2c GET for sysDescr.0 against the well-known 'public' community string."""
    host = target.strip()
    if not host:
        return tool_result("network.snmp_enum", target, status=STATUS_FAILED, error="Empty target")

    probe = _snmp_get(host, community, timeout)
    findings: list[Finding] = []

    if probe.get("responded"):
        sysdescr = probe.get("sysdescr")
        findings.append(Finding(
            title=f"SNMP responds on {host}:{_SNMP_PORT} with community '{community}'",
            severity="high",
            confidence="certain",
            affected_asset=f"{host}:{_SNMP_PORT}/udp",
            evidence=f"sysDescr.0 = {sysdescr!r}" if sysdescr else f"raw response: {probe.get('raw_response_hex')}",
            remediation="Disable the default/guessable community string; restrict SNMP to a "
                        "management VLAN; prefer SNMPv3 with authentication and encryption.",
            tool="network.snmp_enum",
            references=["CWE-521", "CWE-287", "CIS-Benchmark-SNMP"],
        ))
        return tool_result(
            "network.snmp_enum", target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"SNMP with community '{community}' is exposed on {host}",
            metadata={"probe": probe},
        )

    return tool_result(
        "network.snmp_enum", target,
        status=STATUS_NO_FINDINGS,
        summary=f"No SNMP response from {host}:{_SNMP_PORT}/udp with community '{community}' "
                f"(port closed/filtered, or community string rejected)",
        metadata={"probe": probe},
    )


# Register with tool registry
tool_registry.register("network.snmp_enum", run, metadata={
    "name": "network.snmp_enum",
    "domain": "network",
    "status": "completed",
    "description": "Real hand-encoded SNMPv2c GET (sysDescr.0) with the well-known 'public' community string over UDP/161",
    "parameters": {
        "target": "Target IP or hostname",
        "community": "SNMP community string to test (default: 'public')",
        "timeout": "UDP response timeout in seconds (default: 3.0)",
    },
})
