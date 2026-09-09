"""domain_enum.py, gpo_analysis.py, priv_escalation.py, silver_ticket.py,
lateral_movement.py, and pass_the_ticket.py in nexus/tools/active_directory
used to be generic "DNS resolve + bare HTTP GET" stubs identical to dozens
of other tool files across the codebase — never touched LDAP/Kerberos at
all despite their names. Caught during this session's audit. Now: real
anonymous-bind LDAP queries (domain_enum/gpo_analysis/priv_escalation),
real TCP-reachability probing of lateral-movement/Kerberos-relevant
services (lateral_movement/pass_the_ticket), and an honest
credential-required degrade for ticket-material-dependent tools
(silver_ticket/pass_the_ticket) — matching kerberoast.py's/
golden_ticket.py's established honest-degrade convention in the same
directory."""
import socket
from unittest.mock import MagicMock, patch

import pytest

from nexus.tools.active_directory import (
    domain_enum,
    golden_ticket,
    gpo_analysis,
    lateral_movement,
    pass_the_ticket,
    priv_escalation,
    silver_ticket,
)


# ── domain_enum.py ──────────────────────────────────────────────────────

def test_domain_enum_unavailable_when_ldap3_missing():
    with patch.dict("sys.modules", {"ldap3": None}):
        result = domain_enum.run("dc01.example.com")
    assert result["status"] == "unavailable"
    assert not result["findings"]


def test_domain_enum_requires_credentials_on_rejected_bind():
    fake_connection = MagicMock()
    fake_connection.bind.return_value = False
    fake_connection.result = {"description": "invalidCredentials"}
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection):
        result = domain_enum.run("dc01.example.com")
    assert result["status"] == "requires_credentials"
    assert not result["findings"]


def test_domain_enum_reports_real_object_counts():
    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.server.info.other = {"defaultNamingContext": ["DC=example,DC=com"]}
    fake_connection.server.info.vendor_name = "Microsoft"
    fake_connection.server.info.server_type = "AD"
    fake_connection.entries = [MagicMock(), MagicMock()]
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = domain_enum.run("dc01.example.com")
    assert result["status"] == "completed"
    assert result["metadata"]["base_dn"] == "DC=example,DC=com"
    assert result["metadata"]["object_counts"]["users"] == 2


# ── gpo_analysis.py ─────────────────────────────────────────────────────

def test_gpo_analysis_no_findings_when_no_gpos():
    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.other = {"defaultNamingContext": ["DC=example,DC=com"]}
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.entries = []
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = gpo_analysis.run("dc01.example.com")
    assert result["status"] == "no_findings"


def test_gpo_analysis_reports_real_gpos():
    fake_entry = MagicMock()
    fake_entry.displayName = "Default Domain Policy"
    fake_entry.cn = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    fake_entry.gPCFileSysPath = r"\\example.com\SysVol\example.com\Policies\{...}"
    fake_entry.versionNumber = "5"
    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.other = {"defaultNamingContext": ["DC=example,DC=com"]}
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.entries = [fake_entry]
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = gpo_analysis.run("dc01.example.com")
    assert result["status"] == "completed"
    assert "Default Domain Policy" in result["metadata"]["gpos_found"][0]["name"]


# ── priv_escalation.py ──────────────────────────────────────────────────

def test_priv_escalation_flags_unconstrained_delegation():
    admin_entry = MagicMock()
    admin_entry.sAMAccountName = "svc_backup"
    deleg_entry = MagicMock()
    deleg_entry.sAMAccountName = "web-server01"

    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.other = {"defaultNamingContext": ["DC=example,DC=com"]}
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.search.side_effect = [None, None]
    # First .search() populates .entries for adminCount query, second for delegation query
    entries_sequence = [[admin_entry], [deleg_entry]]

    def fake_search(*args, **kwargs):
        fake_connection.entries = entries_sequence.pop(0)

    fake_connection.search.side_effect = fake_search
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = priv_escalation.run("dc01.example.com")
    assert result["status"] == "completed"
    assert "svc_backup" in result["metadata"]["admincount_accounts"]
    assert "web-server01" in result["metadata"]["unconstrained_delegation_accounts"]


# ── silver_ticket.py / pass_the_ticket.py ───────────────────────────────

def test_silver_ticket_requires_credentials_without_ticket_path():
    result = silver_ticket.run("dc01.example.com")
    assert result["status"] == "requires_credentials"
    assert not result["findings"]


def test_silver_ticket_validates_real_kirbi_header(tmp_path):
    ticket_file = tmp_path / "fake.kirbi"
    ticket_file.write_bytes(b"\x76\x82\x05\x00" + b"\x00" * 50)  # KRB-CRED [APPLICATION 22] tag
    result = silver_ticket.run("dc01.example.com", ticket_path=str(ticket_file))
    assert result["status"] == "completed"
    assert result["metadata"]["format"] == "kirbi"


def test_silver_ticket_fails_on_invalid_file(tmp_path):
    bad_file = tmp_path / "not_a_ticket.bin"
    bad_file.write_bytes(b"not a kerberos ticket at all")
    result = silver_ticket.run("dc01.example.com", ticket_path=str(bad_file))
    assert result["status"] == "failed"


def test_pass_the_ticket_requires_credentials_without_ticket_path():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        result = pass_the_ticket.run("dc01.example.com")
    assert result["status"] == "requires_credentials"
    assert not result["findings"]
    assert result["metadata"]["kerberos_port_88_reachable"] is False


def test_pass_the_ticket_validates_real_ccache_header_and_reachability(tmp_path):
    ticket_file = tmp_path / "krb5cc_1000"
    ticket_file.write_bytes(b"\x05\x04" + b"\x00" * 50)  # ccache version marker
    with patch("socket.create_connection", return_value=MagicMock(__enter__=lambda s: s, __exit__=lambda *a: None)):
        result = pass_the_ticket.run("dc01.example.com", ticket_path=str(ticket_file))
    assert result["status"] == "completed"
    assert result["metadata"]["format"] == "ccache"
    assert result["metadata"]["kerberos_port_88_reachable"] is True
    assert result["findings"][0]["severity"] == "high"


# ── lateral_movement.py ─────────────────────────────────────────────────

def test_lateral_movement_no_findings_when_all_ports_closed():
    with patch("socket.gethostbyname", return_value="10.0.0.5"), \
         patch("socket.create_connection", side_effect=OSError("refused")):
        result = lateral_movement.run("host.example.com")
    assert result["status"] == "no_findings"


def test_lateral_movement_reports_real_reachable_smb():
    def fake_connect(addr, timeout=None):
        if addr[1] == 445:
            return MagicMock(__enter__=lambda s: s, __exit__=lambda *a: None)
        raise OSError("refused")

    with patch("socket.gethostbyname", return_value="10.0.0.5"), \
         patch("socket.create_connection", side_effect=fake_connect):
        result = lateral_movement.run("host.example.com")
    assert result["status"] == "completed"
    assert any(s["port"] == 445 for s in result["metadata"]["reachable_services"])


def test_lateral_movement_dns_failure_is_honest_failed_not_crash():
    with patch("socket.gethostbyname", side_effect=socket.gaierror("no such host")):
        result = lateral_movement.run("nonexistent.invalid")
    assert result["status"] == "failed"


# ── golden_ticket.py ─────────────────────────────────────────────────────
# Previously hardcoded `krbtgt_age_days = 1825` behind a "# Simulate
# querying" comment — always the same finding regardless of target, no
# network call ever made. An earlier audit pass wrongly cleared this file
# as already-real; caught and fixed in a follow-up pass. Now: a real LDAP
# query of krbtgt's pwdLastSet, mirroring kerberoast.py's honest pattern.

def test_golden_ticket_requires_credentials_on_rejected_bind():
    fake_connection = MagicMock()
    fake_connection.bind.return_value = False
    fake_connection.result = {"description": "invalidCredentials"}
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection):
        result = golden_ticket.run("dc01.example.com")
    assert result["status"] == "requires_credentials"
    assert not result["findings"]


def test_golden_ticket_requires_credentials_when_pwdlastset_unreadable():
    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.entries = []
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = golden_ticket.run("dc01.example.com")
    assert result["status"] == "requires_credentials"
    assert not result["findings"]


def test_golden_ticket_flags_stale_krbtgt_password_from_real_query():
    import datetime

    stale = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
    filetime = int((stale - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds() * 10_000_000)

    fake_entry = MagicMock()
    fake_entry.pwdLastSet.raw_values = [str(filetime)]
    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.entries = [fake_entry]
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = golden_ticket.run("dc01.example.com")
    assert result["status"] == "completed"
    assert result["metadata"]["krbtgt_age_days"] >= 399
    assert result["findings"][0]["severity"] in ("medium", "high")
    assert "high" == result["findings"][0]["severity"] or result["metadata"]["krbtgt_age_days"] <= 1825


def test_golden_ticket_reports_healthy_age_as_info_not_high():
    import datetime

    fresh = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    filetime = int((fresh - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds() * 10_000_000)

    fake_entry = MagicMock()
    fake_entry.pwdLastSet.raw_values = [str(filetime)]
    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.entries = [fake_entry]
    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = golden_ticket.run("dc01.example.com")
    assert result["status"] == "completed"
    assert result["findings"][0]["severity"] == "info"
    assert result["metadata"]["krbtgt_age_days"] < 180
