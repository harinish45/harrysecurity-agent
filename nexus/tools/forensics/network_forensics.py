#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.network_forensics
Domain: forensics
Real pcap analysis: if the optional `scapy` library is installed (it is, in
this environment) and target is a local .pcap/.pcapng file, parses it via
`scapy.rdpcap` and summarizes real protocol/IP/port breakdown (packet counts
by protocol, top source/destination IPs, top destination ports). Honest-
degrades when scapy isn't installed, or target isn't a recognized capture
file.
"""
from __future__ import annotations
import os
from collections import Counter
from typing import Any
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

MAX_PACKETS = 20000
TOP_N = 10

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\x3c\x4d": "pcap-ns",
    b"\x4d\x3c\xb2\xa1": "pcap-ns",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def _detect_capture_format(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return ""
    return PCAP_MAGICS.get(head, "")


def run(target: str, **kwargs: Any) -> dict:
    """Parse a local pcap file with scapy and summarize protocol/IP/port breakdown."""
    if not target or not os.path.isfile(target):
        return tool_result(
            "forensics.network_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a readable local file — network forensics requires a local "
                    ".pcap/.pcapng capture file path, not a live network target.",
            error="target is not a local file",
        )

    fmt = _detect_capture_format(target)
    if not fmt:
        return tool_result(
            "forensics.network_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary="File does not start with a recognized pcap/pcapng magic-byte header — not a "
                    "valid packet capture.",
            error="unrecognized capture file format",
        )

    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    except ImportError:
        return tool_result(
            "forensics.network_forensics", target,
            status=STATUS_UNAVAILABLE,
            findings=[Finding(
                title="scapy library not installed",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence="The 'scapy' module is required to parse pcap files.",
                remediation="pip install scapy",
                tool="forensics.network_forensics",
                references=[],
            )],
            summary="Network forensics unavailable: scapy not installed.",
            metadata={"format": fmt},
        )

    try:
        packets = rdpcap(target, count=MAX_PACKETS)
    except Exception as e:
        return tool_result("forensics.network_forensics", target, status=STATUS_FAILED, error=f"Failed to parse pcap: {e}")

    proto_counts: Counter = Counter()
    src_ips: Counter = Counter()
    dst_ips: Counter = Counter()
    dst_ports: Counter = Counter()

    for pkt in packets:
        if pkt.haslayer(TCP):
            proto_counts["TCP"] += 1
            dst_ports[int(pkt[TCP].dport)] += 1
        elif pkt.haslayer(UDP):
            proto_counts["UDP"] += 1
            dst_ports[int(pkt[UDP].dport)] += 1
        elif pkt.haslayer(ICMP):
            proto_counts["ICMP"] += 1
        else:
            proto_counts["other"] += 1

        if pkt.haslayer(IP):
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1
        elif pkt.haslayer(IPv6):
            src_ips[pkt[IPv6].src] += 1
            dst_ips[pkt[IPv6].dst] += 1

    findings = [Finding(
        title="Network capture summarized",
        severity="info",
        confidence="certain",
        affected_asset=target,
        evidence=f"Parsed {len(packets)} packet(s). Protocol breakdown: {dict(proto_counts)}. "
                 f"Top source IPs: {src_ips.most_common(TOP_N)}. Top destination ports: {dst_ports.most_common(TOP_N)}.",
        remediation="Review top talkers/ports for unexpected external destinations, unusual protocol mixes, or beaconing patterns.",
        tool="forensics.network_forensics",
    )] if packets else []

    status = STATUS_COMPLETED if packets else STATUS_NO_FINDINGS
    summary = f"Parsed {len(packets)} packet(s) from {fmt} capture; {sum(proto_counts.values())} classified by protocol."
    return tool_result(
        "forensics.network_forensics", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={
            "format": fmt,
            "packet_count": len(packets),
            "protocol_counts": dict(proto_counts),
            "top_src_ips": src_ips.most_common(TOP_N),
            "top_dst_ips": dst_ips.most_common(TOP_N),
            "top_dst_ports": dst_ports.most_common(TOP_N),
        },
    )


tool_registry.register("forensics.network_forensics", run, metadata={
    "name": "forensics.network_forensics",
    "domain": "forensics",
    "status": "completed",
    "description": "Parses a local .pcap/.pcapng capture file via scapy and summarizes real protocol/IP/port breakdown (requires scapy)",
    "parameters": {"target": "Path to a local .pcap/.pcapng capture file"},
})
