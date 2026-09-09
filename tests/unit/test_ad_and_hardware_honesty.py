"""kerberoast.py used to fabricate SPN findings unconditionally
(string-templated from the target name, no real LDAP query ever made);
usb_attacks.py/rfid_testing.py ignored `target` entirely and reported the
local machine's platform info as "completed" target coverage. All three
now either do real work or honestly report a non-completed status instead
of fabricating results — caught during this session's audit."""
from unittest.mock import MagicMock, patch

import pytest

from nexus.tools.active_directory import kerberoast
from nexus.tools.hardware import rfid_testing, usb_attacks
from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE


# ── kerberoast.py ─────────────────────────────────────────────────────────

def test_kerberoast_returns_unavailable_when_ldap3_not_installed():
    with patch.dict("sys.modules", {"ldap3": None}):
        result = kerberoast.run("dc01.example.com")
    assert result["status"] == "unavailable"
    assert not result["findings"]


def test_kerberoast_returns_requires_credentials_on_rejected_anonymous_bind():
    fake_connection = MagicMock()
    fake_connection.bind.return_value = False
    fake_connection.result = {"description": "invalidCredentials"}

    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection):
        result = kerberoast.run("dc01.example.com")

    assert result["status"] == "requires_credentials"
    assert not result["findings"]


def test_kerberoast_returns_unavailable_on_connection_failure():
    with patch("ldap3.Server", side_effect=OSError("connection refused")):
        result = kerberoast.run("not-a-dc.example.com")

    assert result["status"] == "unavailable"
    assert not result["findings"]


def test_kerberoast_reports_real_spns_from_a_genuine_search_response():
    fake_entry = MagicMock()
    fake_entry.sAMAccountName = "svc_sql"
    fake_entry.servicePrincipalName = ["MSSQLSvc/db01.example.com:1433"]

    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.entries = [fake_entry]

    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = kerberoast.run("dc01.example.com")

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "MSSQLSvc/db01.example.com:1433" in result["findings"][0]["evidence"]
    assert result["metadata"]["spns_found"] == ["MSSQLSvc/db01.example.com:1433"]


def test_kerberoast_no_findings_when_search_returns_nothing():
    fake_connection = MagicMock()
    fake_connection.bind.return_value = True
    fake_connection.server.info.naming_contexts = ["DC=example,DC=com"]
    fake_connection.entries = []

    with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
         patch("ldap3.SUBTREE", "SUBTREE"):
        result = kerberoast.run("dc01.example.com")

    assert result["status"] == "no_findings"
    assert result["findings"] == []


# ── hardware honesty ─────────────────────────────────────────────────────

@pytest.mark.parametrize("module", [usb_attacks, rfid_testing])
def test_hardware_tools_honestly_require_hardware(module):
    result = module.run("192.168.1.50")
    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert result["status"] == "requires_hardware"


@pytest.mark.parametrize("module", [usb_attacks, rfid_testing])
def test_hardware_tools_do_not_claim_target_coverage(module):
    result = module.run("192.168.1.50")
    # The local-machine platform info is allowed as diagnostic metadata, but
    # must never be reported as a completed assessment of the target.
    assert result["status"] != "completed"
    assert "192.168.1.50" not in result.get("metadata", {}).get("local_platform", "")
