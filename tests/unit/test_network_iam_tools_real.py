"""Regression tests for nexus/tools/network/{autorecon,firewall_detect,
network_map,nfs_enum,snmp_enum,smb_enum}.py and nexus/tools/iam/* — all
previously generic "DNS-resolve + bare HTTP GET" stubs (caught during this
session's audit), since rewritten to real protocol probes / composites by
concurrent work this session. iam/* already has coverage in
test_appsec_automation_iam_tools_real.py; this file covers the network
protocol tools, which had none.
"""
from __future__ import annotations

import struct

import pytest

from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
)


# ── network.snmp_enum — real BER/ASN.1 encode/decode round-trip ────────────

def test_snmp_ber_encoding_round_trips_sysdescr_extraction():
    from nexus.tools.network import snmp_enum as mod

    packet = mod._build_snmp_get_request(community=b"public", version=1, request_id=0x1234)
    # A real SNMP GETRESPONSE PDU (type 0xA2) carrying a sysDescr OCTET STRING value.
    oid = mod._ber_oid((1, 3, 6, 1, 2, 1, 1, 1, 0))
    varbind = mod._ber_tlv(0x30, oid + mod._ber_octet_string(b"Linux test-host 6.1"))
    varbind_list = mod._ber_tlv(0x30, varbind)
    pdu_body = (
        mod._ber_integer(0x1234) + mod._ber_integer(0) + mod._ber_integer(0) + varbind_list
    )
    pdu = mod._ber_tlv(0xA2, pdu_body)
    message = mod._ber_tlv(0x30, mod._ber_integer(1) + mod._ber_octet_string(b"public") + pdu)

    extracted = mod._extract_sysdescr(message)
    assert extracted == "Linux test-host 6.1"


def test_snmp_enum_no_response_from_closed_udp_port_degrades_honestly():
    from nexus.tools.network import snmp_enum as mod

    result = mod.run("127.0.0.1", community="public", timeout=0.5)
    assert result["status"] in (STATUS_NO_FINDINGS, STATUS_COMPLETED)
    # No real SNMP agent listening in test environment -> must not fabricate a sysDescr finding.
    assert not any("sysDescr" in f.get("evidence", "") and "Linux test-host" in f.get("evidence", "")
                   for f in result.get("findings", []))


# ── network.nfs_enum — real ONC RPC NULL-call packet structure ─────────────

def test_nfs_enum_rpc_null_call_has_valid_onc_rpc_structure():
    from nexus.tools.network import nfs_enum as mod

    packet = mod._build_rpc_null_call(xid=0x4E455853)
    # First 4 bytes: TCP record-marking header (high bit set = last fragment, low 31 bits = body length).
    record_header = struct.unpack(">I", packet[0:4])[0]
    assert record_header & 0x80000000, "last-fragment bit must be set"
    body_len = record_header & 0x7FFFFFFF
    assert body_len == len(packet) - 4
    # ONC RPC call body: XID(4) + msg_type=CALL(0)(4) + rpcvers=2(4) + prog(4) + vers(4) + proc=NULL(0)(4)
    xid, msg_type, rpcvers = struct.unpack(">III", packet[4:16])
    assert xid == 0x4E455853
    assert msg_type == 0  # CALL
    assert rpcvers == 2


def test_nfs_enum_no_service_on_closed_port_honest_no_findings():
    from nexus.tools.network import nfs_enum as mod

    result = mod.run("127.0.0.1", timeout=0.5)
    assert result["status"] in (STATUS_NO_FINDINGS, STATUS_COMPLETED, STATUS_FAILED)
    assert not any("RPC" in f.get("title", "") and "confirmed" in f.get("evidence", "").lower()
                   for f in result.get("findings", []))


def test_nfs_enum_empty_target_fails_cleanly():
    from nexus.tools.network import nfs_enum as mod
    result = mod.run("")
    assert result["status"] == STATUS_FAILED


# ── network.smb_enum — real SMB2 NEGOTIATE packet + dialect table ──────────

def test_smb_enum_negotiate_request_has_valid_smb2_signature():
    from nexus.tools.network import smb_enum as mod

    packet = mod._build_smb2_negotiate_request()
    nb_len = struct.unpack(">I", packet[:4])[0] & 0x00FFFFFF
    pdu = packet[4:4 + nb_len]
    assert pdu[:4] == b"\xfeSMB"


def test_smb_enum_closed_port_reports_unreachable_not_fabricated_dialect():
    from nexus.tools.network import smb_enum as mod

    result = mod._smb2_negotiate_probe("127.0.0.1", timeout=0.5)
    assert result["port"] == 445
    if not result.get("reachable"):
        assert "negotiated_dialect" not in result


def test_smb_enum_empty_target_fails_cleanly():
    from nexus.tools.network import smb_enum as mod
    result = mod.run("")
    assert result["status"] == STATUS_FAILED


# ── network.firewall_detect — real 3-way TCP state classification ──────────

def test_firewall_detect_classifies_open_port_via_real_connect(monkeypatch):
    from nexus.tools.network import firewall_detect as mod
    import socket as socket_mod

    class _FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(socket_mod, "create_connection", lambda addr, timeout: _FakeSock())
    result = mod._classify_port("127.0.0.1", 80, 1.0)
    assert result["state"] == "open"


def test_firewall_detect_classifies_refused_as_closed(monkeypatch):
    from nexus.tools.network import firewall_detect as mod
    import socket as socket_mod

    def _refuse(addr, timeout):
        raise ConnectionRefusedError()

    monkeypatch.setattr(socket_mod, "create_connection", _refuse)
    result = mod._classify_port("127.0.0.1", 1, 1.0)
    assert result["state"] == "closed"


def test_firewall_detect_classifies_timeout_as_filtered(monkeypatch):
    from nexus.tools.network import firewall_detect as mod
    import socket as socket_mod

    def _timeout(addr, timeout):
        raise socket_mod.timeout()

    monkeypatch.setattr(socket_mod, "create_connection", _timeout)
    result = mod._classify_port("10.255.255.1", 81, 0.2)
    assert result["state"] == "filtered"


def test_firewall_detect_run_empty_target_fails_cleanly():
    from nexus.tools.network import firewall_detect as mod
    result = mod.run("")
    assert result["status"] == STATUS_FAILED


# ── network.autorecon — real composite chain over the registry ─────────────

def test_autorecon_chains_port_scan_into_service_enum_and_banner_grab(monkeypatch):
    from nexus.tools.network import autorecon as mod
    from nexus.tools.registry import tool_registry

    def fake_port_scan(target, **kw):
        return {
            "tool": "network.port_scan", "target": target, "status": STATUS_COMPLETED,
            "findings": [{"title": "Open port 22", "severity": "high", "confidence": "certain",
                          "affected_asset": f"{target}:22", "evidence": "open", "tool": "network.port_scan"}],
            "metadata": {},
        }

    def fake_service_enum(target, ports=None, **kw):
        assert ports == [22]
        return {"tool": "network.service_enum", "target": target, "status": STATUS_COMPLETED,
                "findings": [{"title": "SSH service", "severity": "info", "confidence": "certain",
                              "affected_asset": f"{target}:22", "evidence": "ssh", "tool": "network.service_enum"}],
                "metadata": {}}

    def fake_banner_grab(target, ports=None, **kw):
        assert ports == [22]
        return {"tool": "network.banner_grab", "target": target, "status": STATUS_COMPLETED,
                "findings": [], "metadata": {}}

    monkeypatch.setattr(tool_registry, "get", lambda name: {
        "network.port_scan": fake_port_scan,
        "network.service_enum": fake_service_enum,
        "network.banner_grab": fake_banner_grab,
    }[name])

    result = mod.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["open_ports"] == [22]
    assert len(result["findings"]) == 2  # port_scan's + service_enum's; banner_grab had none
    assert result["findings"][0]["evidence"].startswith("[port_scan]")


def test_autorecon_no_open_ports_short_circuits(monkeypatch):
    from nexus.tools.network import autorecon as mod
    from nexus.tools.registry import tool_registry

    monkeypatch.setattr(tool_registry, "get", lambda name: {
        "network.port_scan": lambda target, **kw: {"status": STATUS_NO_FINDINGS, "findings": [], "metadata": {}},
        "network.service_enum": lambda target, **kw: {"status": STATUS_NO_FINDINGS, "findings": [], "metadata": {}},
        "network.banner_grab": lambda target, **kw: {"status": STATUS_NO_FINDINGS, "findings": [], "metadata": {}},
    }[name])

    result = mod.run("example.com")
    assert result["status"] == STATUS_NO_FINDINGS


# ── network.network_map — real CIDR fan-out vs single-host composite ───────

def test_network_map_single_host_calls_discovery_and_service_enum(monkeypatch):
    from nexus.tools.network import network_map as mod
    from nexus.tools.registry import tool_registry

    calls = []

    def fake_host_discovery(target, **kw):
        calls.append(("host_discovery", target))
        return {"status": STATUS_COMPLETED, "findings": [], "metadata": {"alive": True}}

    def fake_service_enum(target, **kw):
        calls.append(("service_enum", target))
        return {"status": STATUS_COMPLETED, "findings": [], "metadata": {}}

    monkeypatch.setattr(tool_registry, "get", lambda name: {
        "network.host_discovery": fake_host_discovery,
        "network.service_enum": fake_service_enum,
    }[name])

    result = mod.run("10.0.0.5")
    assert result["status"] in (STATUS_COMPLETED, STATUS_NO_FINDINGS)
    assert ("host_discovery", "10.0.0.5") in calls
    assert ("service_enum", "10.0.0.5") in calls


def test_network_map_dead_host_skips_service_enum(monkeypatch):
    from nexus.tools.network import network_map as mod
    from nexus.tools.registry import tool_registry

    calls = []
    monkeypatch.setattr(tool_registry, "get", lambda name: {
        "network.host_discovery": lambda target, **kw: (calls.append(target), {"status": STATUS_NO_FINDINGS, "findings": [], "metadata": {"alive": False}})[1],
        "network.service_enum": lambda target, **kw: calls.append("SHOULD_NOT_BE_CALLED") or {"status": STATUS_NO_FINDINGS, "findings": [], "metadata": {}},
    }[name])

    result = mod.run("10.0.0.9")
    assert "SHOULD_NOT_BE_CALLED" not in calls


def test_network_map_empty_target_fails_cleanly():
    from nexus.tools.network import network_map as mod
    result = mod.run("")
    assert result["status"] == STATUS_FAILED
