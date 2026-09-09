"""Real-logic and honest-degrade coverage for the 30 scattered-domain tools
fixed in this session's audit (hardware, network, reverse_engineering,
rf_sdr, cryptography, iot, ot_ics). Each group previously shared one
byte-for-byte-identical fake implementation (DNS resolve + bare HTTP GET
on `/`, unrelated to the tool's actual name) unconditionally reporting
status "completed". This suite verifies each tool now either performs
real, protocol-correct work (mocked at the socket boundary where no live
target/hardware is available) or honestly reports a non-completed status
(STATUS_REQUIRES_HARDWARE / STATUS_UNAVAILABLE / STATUS_REQUIRES_CREDENTIALS
/ STATUS_OUT_OF_SCOPE) instead of fabricating results — this dev machine
has none of the physical hardware (TPM query aside), SDR, JTAG/UART, or
credentialed APIs these tools would otherwise require.
"""
from __future__ import annotations

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_REQUIRES_HARDWARE,
    STATUS_UNAVAILABLE,
)


def _fake_conn(recv_data: bytes = b"", raise_on_connect: Exception | None = None):
    """A context-manager-shaped fake socket for patching socket.create_connection."""
    if raise_on_connect:
        raise raise_on_connect
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    conn.recv.return_value = recv_data
    return conn


# ═════════════════════════════════════════════════════════════════════════
# hardware
# ═════════════════════════════════════════════════════════════════════════

from nexus.tools.hardware import (
    fault_injection,
    nfc_testing,
    rubber_ducky_testing,
    secure_boot_testing,
    side_channel_analysis,
    tpm_analysis,
)

_HARDWARE_ALWAYS_DEGRADE = [fault_injection, nfc_testing, rubber_ducky_testing, side_channel_analysis]


@pytest.mark.parametrize("module", _HARDWARE_ALWAYS_DEGRADE)
def test_hardware_tools_honestly_require_hardware(module):
    result = module.run("192.168.1.50")
    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "192.168.1.50" not in result.get("metadata", {}).get("local_platform", "")


def test_hardware_tools_have_distinct_explanations():
    summaries = {m.__name__: m.run("t")["summary"] for m in _HARDWARE_ALWAYS_DEGRADE}
    assert len(set(summaries.values())) == len(summaries), f"duplicate explanations: {summaries}"


def test_tpm_analysis_always_requires_hardware_for_remote_target():
    result = tpm_analysis.run("192.168.1.50")
    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "local_tpm_probe" in result["metadata"]


def test_tpm_analysis_real_probe_reflects_absent_device_on_linux(monkeypatch):
    monkeypatch.setattr("os.name", "posix")
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr("os.path.isdir", lambda p: False)
    result = tpm_analysis.run("target.example.com")
    assert result["metadata"]["local_tpm_probe"]["tpm_device_present"] is False


def test_secure_boot_testing_always_requires_hardware_for_remote_target():
    with patch("shutil.which", return_value=None):
        result = secure_boot_testing.run("192.168.1.50")
    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "local_secure_boot_probe" in result["metadata"]


# ═════════════════════════════════════════════════════════════════════════
# network
# ═════════════════════════════════════════════════════════════════════════

from nexus.tools.network import (
    autorecon,
    firewall_detect,
    network_map,
    nfs_enum,
    smb_enum,
    snmp_enum,
)


def test_nfs_enum_parses_real_rpc_null_reply():
    xid, msg_type, reply_stat = 0x4E455853, 1, 0  # REPLY, MSG_ACCEPTED
    body = struct.pack(">III", xid, msg_type, reply_stat)
    frag_hdr = struct.pack(">I", 0x80000000 | len(body))
    pm_reply = _fake_conn(recv_data=frag_hdr + body)
    nfsd_conn = _fake_conn()

    with patch("socket.create_connection", side_effect=[pm_reply, nfsd_conn]), \
         patch("shutil.which", return_value=None):
        result = nfs_enum.run("10.0.0.5")

    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("portmapper responding" in t for t in titles)
    assert any("NFS server port open" in t for t in titles)


def test_nfs_enum_no_findings_when_ports_closed():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError()), \
         patch("shutil.which", return_value=None):
        result = nfs_enum.run("10.0.0.5")
    assert result["status"] == STATUS_NO_FINDINGS


def test_smb_enum_parses_real_smb2_negotiate_response():
    header = b"\xfeSMB" + b"\x00" * 60
    body = struct.pack("<H", 65) + struct.pack("<H", 1) + struct.pack("<H", 0x0202) + b"\x00" * 10
    pdu = header + body
    response = struct.pack(">I", len(pdu)) + pdu
    conn = _fake_conn(recv_data=response)

    with patch("socket.create_connection", return_value=conn), \
         patch("shutil.which", return_value=None):
        result = smb_enum.run("10.0.0.5")

    assert result["status"] == STATUS_COMPLETED
    assert any("SMB 2.0.2" in f["title"] for f in result["findings"])


def test_smb_enum_flags_smb1_as_high_severity():
    header = b"\xffSMB" + b"\x00" * 60
    response = struct.pack(">I", len(header)) + header
    conn = _fake_conn(recv_data=response)

    with patch("socket.create_connection", return_value=conn), \
         patch("shutil.which", return_value=None):
        result = smb_enum.run("10.0.0.5")

    smb1_finding = next(f for f in result["findings"] if "SMB1" in f["title"])
    assert smb1_finding["severity"] == "high"


def _build_snmp_getresponse(sysdescr: bytes, community: bytes = b"public", request_id: int = 0x1234) -> bytes:
    from nexus.tools.network.snmp_enum import _SYSDESCR_OID, _ber_integer, _ber_octet_string, _ber_oid, _ber_tlv
    varbind = _ber_tlv(0x30, _ber_oid(_SYSDESCR_OID) + _ber_octet_string(sysdescr))
    varbind_list = _ber_tlv(0x30, varbind)
    pdu_body = _ber_integer(request_id) + _ber_integer(0) + _ber_integer(0) + varbind_list
    pdu = _ber_tlv(0xA2, pdu_body)
    message = _ber_integer(1) + _ber_octet_string(community) + pdu
    return _ber_tlv(0x30, message)


def test_snmp_enum_parses_real_ber_getresponse():
    response = _build_snmp_getresponse(b"Test Router v1.2.3")
    fake_sock = MagicMock()
    fake_sock.recvfrom.return_value = (response, ("10.0.0.5", 161))

    with patch("socket.socket", return_value=fake_sock):
        result = snmp_enum.run("10.0.0.5")

    assert result["status"] == STATUS_COMPLETED
    assert "Test Router v1.2.3" in result["findings"][0]["evidence"]
    assert result["findings"][0]["severity"] == "high"


def test_snmp_enum_encoder_produces_well_formed_request():
    from nexus.tools.network.snmp_enum import _SYSDESCR_OID, _build_snmp_get_request, _parse_tlv
    request = _build_snmp_get_request(b"public", version=1, request_id=42)
    tag, message, _ = _parse_tlv(request, 0)
    assert tag == 0x30
    version_tag, version_val, pos = _parse_tlv(message, 0)
    assert version_val == b"\x01"  # SNMPv2c
    community_tag, community_val, pos = _parse_tlv(message, pos)
    assert community_val == b"public"


def test_snmp_enum_no_findings_on_timeout():
    fake_sock = MagicMock()
    fake_sock.recvfrom.side_effect = socket.timeout()
    with patch("socket.socket", return_value=fake_sock):
        result = snmp_enum.run("10.0.0.5")
    assert result["status"] == STATUS_NO_FINDINGS


def test_firewall_detect_classifies_open_closed_filtered():
    def connect_side_effect(addr, timeout=None):
        host, port = addr
        if port == 22:
            return _fake_conn()
        if port == 80:
            raise ConnectionRefusedError()
        raise socket.timeout()

    with patch("socket.create_connection", side_effect=connect_side_effect):
        result = firewall_detect.run("10.0.0.5", ports=[22, 80, 443])

    states = {f["title"].split(": ")[0]: f["title"].split(": ")[1] for f in result["findings"] if "/tcp on" in f["title"]}
    assert states["Port 22/tcp on 10.0.0.5"] == "open"
    assert states["Port 80/tcp on 10.0.0.5"] == "closed"
    assert states["Port 443/tcp on 10.0.0.5"] == "filtered"
    assert any("Differential filtering detected" in f["title"] for f in result["findings"])


def test_autorecon_chains_port_scan_into_service_enum_and_banner_grab():
    fake_port_scan = MagicMock(return_value={
        "findings": [{"affected_asset": "10.0.0.5:22", "title": "open", "severity": "high"}],
        "metadata": {},
    })
    fake_service_enum = MagicMock(return_value={"findings": [{"affected_asset": "10.0.0.5:22", "title": "ssh", "severity": "high"}], "metadata": {}})
    fake_banner_grab = MagicMock(return_value={"findings": [], "metadata": {}})

    def fake_get(name):
        return {
            "network.port_scan": fake_port_scan,
            "network.service_enum": fake_service_enum,
            "network.banner_grab": fake_banner_grab,
        }[name]

    with patch("nexus.tools.network.autorecon.tool_registry.get", side_effect=fake_get):
        result = autorecon.run("10.0.0.5")

    assert result["status"] == STATUS_COMPLETED
    fake_service_enum.assert_called_once_with(target="10.0.0.5", ports=[22])
    fake_banner_grab.assert_called_once_with(target="10.0.0.5", ports=[22])


def test_autorecon_no_findings_when_no_open_ports():
    fake_port_scan = MagicMock(return_value={"findings": [], "metadata": {}})
    with patch("nexus.tools.network.autorecon.tool_registry.get", return_value=fake_port_scan):
        result = autorecon.run("10.0.0.5")
    assert result["status"] == STATUS_NO_FINDINGS


def test_network_map_fans_out_over_cidr():
    fake_discovery = MagicMock(return_value={"metadata": {"alive": True}, "summary": "alive"})
    fake_service_enum = MagicMock(return_value={"findings": [], "metadata": {"open_count": 0}})

    def fake_get(name):
        return {"network.host_discovery": fake_discovery, "network.service_enum": fake_service_enum}[name]

    with patch("nexus.tools.network.network_map.tool_registry.get", side_effect=fake_get):
        result = network_map.run("192.168.50.0/30", max_hosts=8)

    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["is_cidr"] is True
    assert fake_discovery.call_count == 2  # /30 usable hosts


def test_network_map_no_findings_when_all_hosts_down():
    fake_discovery = MagicMock(return_value={"metadata": {"alive": False}})
    with patch("nexus.tools.network.network_map.tool_registry.get", return_value=fake_discovery):
        result = network_map.run("10.0.0.5")
    assert result["status"] == STATUS_NO_FINDINGS


# ═════════════════════════════════════════════════════════════════════════
# reverse_engineering
# ═════════════════════════════════════════════════════════════════════════

from nexus.tools.reverse_engineering import (
    assembly_analysis,
    binary_patching,
    debugging,
    firmware_reverse_engineering,
    function_analysis,
    symbol_recovery,
)


def _build_synthetic_elf64_with_symtab() -> bytes:
    """A minimal, real ELF64 relocatable object with a genuine .symtab/.strtab/.shstrtab
    section trio, hand-built per the real ELF64 spec (no pyelftools)."""
    strtab = b"\x00main\x00helper_func\x00"
    main_off = 1
    helper_off = 6

    def sym(name_off, value, size, shndx):
        # Elf64_Sym: st_name(I), st_info(B), st_other(B), st_shndx(H), st_value(Q), st_size(Q)
        return struct.pack("<IBBHQQ", name_off, 0x12, 0, shndx, value, size)

    symtab = sym(0, 0, 0, 0) + sym(main_off, 0x1000, 0x20, 1) + sym(helper_off, 0x1020, 0x10, 1)
    shstrtab = b"\x00.symtab\x00.strtab\x00.shstrtab\x00"
    symtab_name_off = 1
    strtab_name_off = 9
    shstrtab_name_off = 17

    ehdr_size = 64
    shentsize = 64
    shnum = 4
    shoff = ehdr_size
    data_off = shoff + shnum * shentsize

    strtab_off = data_off
    symtab_off = strtab_off + len(strtab)
    shstrtab_off = symtab_off + len(symtab)

    def shdr(name_off, sh_type, offset, size, link=0):
        # name(I) type(I) flags(Q) addr(Q) offset(Q) size(Q) link(I) info(I) addralign(Q) entsize(Q)
        return struct.pack("<IIQQQQIIQQ", name_off, sh_type, 0, 0, offset, size, link, 0, 8, 0)

    section_headers = (
        shdr(0, 0, 0, 0) +  # NULL section
        shdr(symtab_name_off, 2, symtab_off, len(symtab), link=2) +  # .symtab (SHT_SYMTAB=2)
        shdr(strtab_name_off, 3, strtab_off, len(strtab)) +          # .strtab (SHT_STRTAB=3)
        shdr(shstrtab_name_off, 3, shstrtab_off, len(shstrtab))      # .shstrtab
    )

    e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    ehdr = (
        e_ident +
        struct.pack("<HHIQQQIHHHHHH",
                    1, 0x3E, 1, 0, 0, shoff, 0, ehdr_size, 0, 0, shentsize, shnum, 3)
    )
    return ehdr + section_headers + strtab + symtab + shstrtab


def test_symbol_recovery_parses_real_elf_symtab(tmp_path):
    elf_bytes = _build_synthetic_elf64_with_symtab()
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf_bytes)

    result = symbol_recovery.run(str(sample))

    assert result["status"] == STATUS_COMPLETED
    names = {s["name"] for s in result["metadata"]["symbols"]}
    assert names == {"main", "helper_func"}
    assert all(s["type"] == "FUNC" for s in result["metadata"]["symbols"])


def test_symbol_recovery_no_findings_on_stripped_elf(tmp_path):
    # A minimal but valid ELF: one section (a self-describing .shstrtab),
    # no .symtab/.dynsym at all -- the real "fully stripped" case.
    shstrtab = b"\x00.shstrtab\x00"
    ehdr_size = 64
    shoff = ehdr_size
    shstrtab_off = shoff + 1 * 64
    e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    ehdr = e_ident + struct.pack("<HHIQQQIHHHHHH", 1, 0x3E, 1, 0, 0, shoff, 0, ehdr_size, 0, 0, 64, 1, 0)
    shdr = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 8, 0)
    sample = tmp_path / "stripped.elf"
    sample.write_bytes(ehdr + shdr + shstrtab)
    result = symbol_recovery.run(str(sample))
    assert result["status"] == STATUS_NO_FINDINGS


def test_symbol_recovery_unrecognised_format_fails_honestly(tmp_path):
    sample = tmp_path / "notabinary.txt"
    sample.write_text("just some text")
    result = symbol_recovery.run(str(sample))
    assert result["status"] == "failed"


def test_firmware_reverse_engineering_finds_embedded_squashfs(tmp_path):
    blob = b"\x00" * 512 + b"hsqs" + b"\x11" * 100 + b"\x1f\x8b" + b"\x22" * 50
    sample = tmp_path / "firmware.bin"
    sample.write_bytes(blob)

    result = firmware_reverse_engineering.run(str(sample))

    assert result["status"] == STATUS_COMPLETED
    hits = result["metadata"]["signature_hits"]
    assert 512 in hits["SquashFS (little-endian)"]
    assert any("gzip" in k for k in hits)


def test_firmware_reverse_engineering_no_findings_on_plain_data(tmp_path):
    sample = tmp_path / "plain.bin"
    sample.write_bytes(b"just plain data, nothing embedded here" * 10)
    result = firmware_reverse_engineering.run(str(sample))
    assert result["status"] == STATUS_NO_FINDINGS


def test_assembly_analysis_honest_fallback_without_capstone(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 20)
    with patch.dict("sys.modules", {"capstone": None}):
        result = assembly_analysis.run(str(sample))
    assert result["status"] == STATUS_UNAVAILABLE
    assert "capstone" in result["findings"][0]["title"] and "not installed" in result["findings"][0]["title"]


def test_function_analysis_honest_fallback_without_capstone(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 20)
    with patch.dict("sys.modules", {"capstone": None}):
        result = function_analysis.run(str(sample))
    assert result["status"] == STATUS_UNAVAILABLE


def test_assembly_analysis_real_disassembly_when_capstone_available(tmp_path):
    pytest.importorskip("capstone")
    # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret  (classic x86 prologue/epilogue)
    code = bytes.fromhex("558bec31c05dc3")
    sample = tmp_path / "raw.bin"
    sample.write_bytes(code)
    result = assembly_analysis.run(str(sample))
    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["instruction_count"] > 0


def test_function_analysis_real_boundary_heuristic_when_capstone_available(tmp_path):
    pytest.importorskip("capstone")
    code = bytes.fromhex("558bec31c05dc3")  # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
    sample = tmp_path / "raw.bin"
    sample.write_bytes(code)
    result = function_analysis.run(str(sample))
    assert result["status"] == STATUS_COMPLETED
    assert len(result["metadata"]["functions"]) >= 1


def test_binary_patching_never_writes_without_explicit_kwargs(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 16)
    original = sample.read_bytes()
    result = binary_patching.run(str(sample))
    assert result["status"] == STATUS_UNAVAILABLE
    assert sample.read_bytes() == original  # never mutated


def test_debugging_honestly_requires_pid_and_debugger():
    result = debugging.run("some-process")
    assert result["status"] == STATUS_UNAVAILABLE


# ═════════════════════════════════════════════════════════════════════════
# rf_sdr
# ═════════════════════════════════════════════════════════════════════════

from nexus.tools.rf_sdr import (
    hackrf_experimentation,
    jammer_detection,
    radio_protocol_analysis,
    replay_testing,
    rtl_sdr_analysis,
    signal_decoding,
)

_RF_SDR_ALWAYS_DEGRADE = [jammer_detection, radio_protocol_analysis, replay_testing, signal_decoding]


@pytest.mark.parametrize("module", _RF_SDR_ALWAYS_DEGRADE)
def test_rf_sdr_tools_honestly_require_hardware(module):
    result = module.run("radio-target")
    assert result["status"] == STATUS_REQUIRES_HARDWARE


def test_rf_sdr_tools_have_distinct_explanations():
    summaries = {m.__name__: m.run("t")["summary"] for m in _RF_SDR_ALWAYS_DEGRADE}
    assert len(set(summaries.values())) == len(summaries)


def test_rtl_sdr_analysis_requires_hardware_when_tools_absent():
    with patch("shutil.which", return_value=None):
        result = rtl_sdr_analysis.run("radio-target")
    assert result["status"] == STATUS_REQUIRES_HARDWARE


def test_rtl_sdr_analysis_real_probe_when_tool_present():
    fake_result = MagicMock(stdout="Found 1 device(s):\n  0:  Realtek, RTL2838UHIDIR\n", returncode=0)
    with patch("shutil.which", return_value="/usr/bin/rtl_test"), \
         patch("nexus.tools.rf_sdr.rtl_sdr_analysis.run_subprocess", return_value=fake_result):
        result = rtl_sdr_analysis.run("radio-target")
    assert result["status"] == STATUS_COMPLETED
    assert "Realtek" in result["findings"][0]["evidence"]


def test_hackrf_experimentation_requires_hardware_when_absent():
    with patch("shutil.which", return_value=None):
        result = hackrf_experimentation.run("radio-target")
    assert result["status"] == STATUS_REQUIRES_HARDWARE


def test_hackrf_experimentation_real_probe_when_present():
    fake_result = MagicMock(stdout="Found HackRF board 0\nSerial number: deadbeef\n", returncode=0)
    with patch("shutil.which", return_value="/usr/bin/hackrf_info"), \
         patch("nexus.tools.rf_sdr.hackrf_experimentation.run_subprocess", return_value=fake_result):
        result = hackrf_experimentation.run("radio-target")
    assert result["status"] == STATUS_COMPLETED
    assert "HackRF" in result["findings"][0]["evidence"]


# ═════════════════════════════════════════════════════════════════════════
# cryptography
# ═════════════════════════════════════════════════════════════════════════

from nexus.tools.cryptography import (
    certificate_validation,
    crypto_hash_analysis,
    cryptanalysis,
    key_management,
    pki_reviews,
)


def _make_self_signed_cert(common_name: str, days_valid: int, self_signed: bool = True):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    not_before = now - dt.timedelta(days=max(2, abs(days_valid) + 2))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_certificate_validation_flags_expired_cert():
    der = _make_self_signed_cert("expired.example.com", days_valid=-30)
    tls_sock = MagicMock()
    tls_sock.getpeercert.return_value = der
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    ctx = MagicMock()
    ctx.wrap_socket.return_value.__enter__.return_value = tls_sock
    ctx.wrap_socket.return_value.__exit__.return_value = False

    with patch("socket.create_connection", return_value=conn), \
         patch("nexus.tools.cryptography.certificate_validation.get_ssl_context", return_value=ctx):
        result = certificate_validation.run("expired.example.com", ports=[443])

    expiry_finding = next(f for f in result["findings"] if "EXPIRED" in f["title"])
    assert expiry_finding["severity"] == "critical"
    self_signed_finding = next(f for f in result["findings"] if "self-signed" in f["title"])
    assert self_signed_finding["severity"] == "medium"


def test_certificate_validation_flags_hostname_mismatch():
    der = _make_self_signed_cert("other-name.example.com", days_valid=365)
    tls_sock = MagicMock()
    tls_sock.getpeercert.return_value = der
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    ctx = MagicMock()
    ctx.wrap_socket.return_value.__enter__.return_value = tls_sock
    ctx.wrap_socket.return_value.__exit__.return_value = False

    with patch("socket.create_connection", return_value=conn), \
         patch("nexus.tools.cryptography.certificate_validation.get_ssl_context", return_value=ctx):
        result = certificate_validation.run("requested-hostname.example.com", ports=[443])

    assert any("does not match hostname" in f["title"] for f in result["findings"])


def test_certificate_validation_healthy_cert_is_low_noise():
    der = _make_self_signed_cert("healthy.example.com", days_valid=365)
    tls_sock = MagicMock()
    tls_sock.getpeercert.return_value = der
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    ctx = MagicMock()
    ctx.wrap_socket.return_value.__enter__.return_value = tls_sock
    ctx.wrap_socket.return_value.__exit__.return_value = False

    with patch("socket.create_connection", return_value=conn), \
         patch("nexus.tools.cryptography.certificate_validation.get_ssl_context", return_value=ctx):
        result = certificate_validation.run("healthy.example.com", ports=[443])

    assert not any(f["severity"] == "critical" for f in result["findings"])
    assert not any("does not match hostname" in f["title"] for f in result["findings"])


def test_pki_reviews_reports_untrusted_chain():
    with patch("nexus.tools.cryptography.pki_reviews._check_chain_of_trust",
               return_value={"trusted": False, "reason": "self-signed certificate"}), \
         patch("nexus.tools.cryptography.pki_reviews.fetch_and_parse_cert", return_value=None):
        result = pki_reviews.run("bad-chain.example.com", ports=[443])

    assert result["status"] == STATUS_COMPLETED
    assert any(f["severity"] == "high" and "does NOT verify" in f["title"] for f in result["findings"])


def test_pki_reviews_reports_trusted_chain():
    with patch("nexus.tools.cryptography.pki_reviews._check_chain_of_trust", return_value={"trusted": True}), \
         patch("nexus.tools.cryptography.pki_reviews.fetch_and_parse_cert", return_value=None):
        result = pki_reviews.run("good-chain.example.com", ports=[443])

    assert any("verifies against system trust store" in f["title"] for f in result["findings"])


def test_crypto_hash_analysis_real_multialgorithm_hash(tmp_path):
    sample = tmp_path / "data.bin"
    sample.write_bytes(b"hello world")
    result = crypto_hash_analysis.run(str(sample))

    assert result["status"] == STATUS_COMPLETED
    import hashlib
    assert result["metadata"]["digests"]["sha256"] == hashlib.sha256(b"hello world").hexdigest()
    assert result["metadata"]["digests"]["md5"] == hashlib.md5(b"hello world", usedforsecurity=False).hexdigest()
    assert any("MD5" in f["title"] and "weak" in f["title"] for f in result["findings"])
    assert any("SHA1" in f["title"] and "weak" in f["title"] for f in result["findings"])


def test_crypto_hash_analysis_out_of_scope_for_non_file_target():
    result = crypto_hash_analysis.run("not-a-real-file-path-xyz")
    assert result["status"] == STATUS_OUT_OF_SCOPE


def test_cryptanalysis_honest_degrade_without_ciphertext():
    result = cryptanalysis.run("example.com")
    assert result["status"] == STATUS_UNAVAILABLE


def test_cryptanalysis_real_caesar_break_with_enough_text():
    plaintext = ("This is a much longer piece of English text used to test whether the chi "
                 "squared frequency analysis correctly recovers the Caesar cipher shift key")
    shift = 7
    ciphertext = "".join(
        chr((ord(c.upper()) - 65 + shift) % 26 + 65) if c.isalpha() else c for c in plaintext
    )
    result = cryptanalysis.run("example.com", ciphertext=ciphertext)
    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["best_shift"] == shift


def test_key_management_requires_credentials_when_no_aws_creds():
    with patch("nexus.tools.cryptography.key_management._has_aws_credentials", return_value=False):
        result = key_management.run("example.com")
    assert result["status"] == STATUS_REQUIRES_CREDENTIALS


def test_key_management_real_kms_review_when_credentials_present():
    fake_client = MagicMock()
    fake_client.list_keys.return_value = {"Keys": [{"KeyId": "abcd-1234", "KeyArn": "arn:aws:kms:...:key/abcd-1234"}]}
    fake_client.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
    fake_boto3 = MagicMock()
    fake_boto3.client.return_value = fake_client

    with patch("nexus.tools.cryptography.key_management._has_aws_credentials", return_value=True), \
         patch.dict("sys.modules", {"boto3": fake_boto3}):
        result = key_management.run("example.com")

    assert result["status"] == STATUS_COMPLETED
    assert "DISABLED" in result["findings"][0]["title"]
    assert result["findings"][0]["severity"] == "medium"


# ═════════════════════════════════════════════════════════════════════════
# iot
# ═════════════════════════════════════════════════════════════════════════

from nexus.tools.iot import can_bus_testing, embedded_linux, jtag_analysis, uart_analysis


def test_uart_analysis_unavailable_without_pyserial():
    with patch.dict("sys.modules", {"serial": None, "serial.tools": None, "serial.tools.list_ports": None}):
        result = uart_analysis.run("target")
    assert result["status"] == STATUS_UNAVAILABLE


def _fake_pyserial_modules(fake_list_ports):
    fake_serial = MagicMock()
    fake_serial_tools = MagicMock()
    fake_serial_tools.list_ports = fake_list_ports
    fake_serial.tools = fake_serial_tools
    return {"serial": fake_serial, "serial.tools": fake_serial_tools, "serial.tools.list_ports": fake_list_ports}


def test_uart_analysis_requires_hardware_when_no_ports_found():
    fake_list_ports = MagicMock()
    fake_list_ports.comports.return_value = []
    with patch.dict("sys.modules", _fake_pyserial_modules(fake_list_ports)):
        result = uart_analysis.run("target")
    assert result["status"] == STATUS_REQUIRES_HARDWARE


def test_uart_analysis_completed_when_local_ports_found():
    fake_port = MagicMock(device="COM3", description="USB Serial Device", hwid="USB VID:PID=0403:6001")
    fake_list_ports = MagicMock()
    fake_list_ports.comports.return_value = [fake_port]
    with patch.dict("sys.modules", _fake_pyserial_modules(fake_list_ports)):
        result = uart_analysis.run("target")
    assert result["status"] == STATUS_COMPLETED


def test_can_bus_testing_unavailable_without_pyserial():
    with patch.dict("sys.modules", {"serial": None, "serial.tools": None, "serial.tools.list_ports": None}):
        result = can_bus_testing.run("target")
    assert result["status"] == STATUS_UNAVAILABLE


def test_jtag_analysis_unavailable_without_pyusb():
    with patch.dict("sys.modules", {"usb": None, "usb.core": None}):
        result = jtag_analysis.run("target")
    assert result["status"] == STATUS_UNAVAILABLE


def test_embedded_linux_out_of_scope_for_non_directory():
    result = embedded_linux.run("not-a-real-directory-xyz")
    assert result["status"] == STATUS_OUT_OF_SCOPE


def test_embedded_linux_flags_busybox_and_weak_root_password(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "busybox").write_bytes(b"\x7fELF fake busybox")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root::0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n")

    result = embedded_linux.run(str(tmp_path))

    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["busybox_found"] is True
    weak_finding = next(f for f in result["findings"] if "Weak root account" in f["title"])
    assert weak_finding["severity"] == "critical"


def test_embedded_linux_no_findings_on_ordinary_directory(tmp_path):
    (tmp_path / "somefile.txt").write_text("nothing embedded-linux-shaped here")
    result = embedded_linux.run(str(tmp_path))
    assert result["status"] == STATUS_NO_FINDINGS


# ═════════════════════════════════════════════════════════════════════════
# ot_ics
# ═════════════════════════════════════════════════════════════════════════

from nexus.tools.ot_ics import dnp3_testing, industrial_protocol_reviews, modbus_analysis, plc_testing, scada_security


def _build_modbus_holding_registers_response(transaction_id=1, unit_id=1, values=(100, 200)):
    data = b"".join(struct.pack(">H", v) for v in values)
    pdu = struct.pack(">BB", 0x03, len(data)) + data
    length = len(pdu) + 1
    mbap = struct.pack(">HHHB", transaction_id, 0, length, unit_id)
    return mbap + pdu


def test_modbus_analysis_parses_real_holding_registers_response():
    response = _build_modbus_holding_registers_response(values=(42, 99))
    conn = _fake_conn(recv_data=response)
    with patch("socket.create_connection", return_value=conn):
        result = modbus_analysis.run("10.0.0.10")

    assert result["status"] == STATUS_COMPLETED
    live_finding = next(f for f in result["findings"] if "live register data" in f["title"])
    assert live_finding["severity"] == "critical"
    assert "002a0063" in live_finding["evidence"]  # 42, 99 in hex


def test_modbus_analysis_parses_real_exception_response():
    pdu = struct.pack(">BB", 0x83, 0x02)  # exception for fn 0x03, code=2 (Illegal Data Address)
    mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1)
    conn = _fake_conn(recv_data=mbap + pdu)
    with patch("socket.create_connection", return_value=conn):
        result = modbus_analysis.run("10.0.0.10")

    exc_finding = next(f for f in result["findings"] if "exception" in f["title"])
    assert "Illegal Data Address" in exc_finding["evidence"]


def test_modbus_analysis_no_findings_when_port_closed():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
        result = modbus_analysis.run("10.0.0.10")
    assert result["status"] == STATUS_NO_FINDINGS


def test_dnp3_crc16_matches_standard_check_value():
    from nexus.tools.ot_ics.dnp3_testing import _crc16_dnp
    assert _crc16_dnp(b"123456789") == 0xEA82


def test_dnp3_testing_detects_real_dnp3_sync_bytes():
    conn = _fake_conn(recv_data=b"\x05\x64\x08\xc0\x01\x00\x01\x00\x00\x00")
    with patch("socket.create_connection", return_value=conn):
        result = dnp3_testing.run("10.0.0.20")

    assert result["status"] == STATUS_COMPLETED
    assert any("DNP3 outstation responding" in f["title"] for f in result["findings"])


def test_dnp3_testing_no_findings_when_port_closed():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
        result = dnp3_testing.run("10.0.0.20")
    assert result["status"] == STATUS_NO_FINDINGS


def test_industrial_protocol_reviews_reports_real_open_ports():
    def connect_side_effect(addr, timeout=None):
        host, port = addr
        if port == 502:
            return _fake_conn()
        raise ConnectionRefusedError()

    with patch("socket.create_connection", side_effect=connect_side_effect), \
         patch("nexus.tools.ot_ics.industrial_protocol_reviews.tool_registry.get",
               side_effect=KeyError("not needed for this test")):
        result = industrial_protocol_reviews.run("10.0.0.10")

    assert result["status"] == STATUS_COMPLETED
    assert any("Modbus TCP" in f["title"] for f in result["findings"])


def test_plc_testing_no_findings_when_all_ports_closed():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
        result = plc_testing.run("10.0.0.10")
    assert result["status"] == STATUS_NO_FINDINGS


def test_scada_security_flags_unauthenticated_hmi_web():
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.read.return_value = b"<html><body>Live process data dashboard</body></html>"
    with patch("nexus.tools.ot_ics.scada_security.safe_urlopen", return_value=fake_resp), \
         patch("socket.create_connection", side_effect=ConnectionRefusedError()):
        result = scada_security.run("10.0.0.10")

    assert result["status"] == STATUS_COMPLETED
    assert any(f["severity"] == "critical" for f in result["findings"])
