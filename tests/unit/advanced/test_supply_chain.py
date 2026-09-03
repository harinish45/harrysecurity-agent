"""Tests for nexus.advanced.supply_chain.

pip-audit is pip-installed in this environment but its console-script entry
point is not on PATH, and even ``python -m pip_audit`` requires network
access (to resolve the vulnerability DB) which is not practical to rely on
in a unit test. So these tests exercise the JSON-parsing logic
(``parse_pip_audit_json``) directly against a canned payload matching
pip-audit's real JSON schema (verified against the installed
``pip_audit._format.json.JsonFormat`` implementation), plus a
FileNotFoundError-tolerance test for the ``scan()`` wrapper itself.
"""
from nexus.advanced.supply_chain import SupplyChainScanner

_CANNED_PIP_AUDIT_JSON = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.6.0",
            "vulns": [
                {
                    "id": "PYSEC-2014-25",
                    "fix_versions": ["2.6.1"],
                    "aliases": ["CVE-2014-1830"],
                    "description": "Requests before 2.6.1 leaks auth headers on redirect.",
                }
            ],
        },
        {
            "name": "flask",
            "version": "0.12",
            "vulns": [
                {
                    "id": "PYSEC-2019-1",
                    "fix_versions": [],
                    "aliases": [],
                    "description": "No fix available yet.",
                }
            ],
        },
        {
            "name": "safe-package",
            "version": "1.0.0",
            "vulns": [],
        },
    ],
    "fixes": [],
}


def test_parse_pip_audit_json_builds_finding_shaped_dicts():
    findings = SupplyChainScanner().parse_pip_audit_json(_CANNED_PIP_AUDIT_JSON)
    assert len(findings) == 2  # safe-package contributes nothing

    requests_finding = next(f for f in findings if f["affected_asset"] == "requests")
    assert requests_finding["title"] == "requests 2.6.0: PYSEC-2014-25"
    assert requests_finding["severity"] == "medium"
    assert requests_finding["tool"] == "supply_chain.pip_audit"
    assert "2.6.1" in requests_finding["remediation"]
    assert "CVE-2014-1830" in requests_finding["references"]
    assert requests_finding["raw"]["severity_note"]


def test_parse_pip_audit_json_flags_missing_fix():
    findings = SupplyChainScanner().parse_pip_audit_json(_CANNED_PIP_AUDIT_JSON)
    flask_finding = next(f for f in findings if f["affected_asset"] == "flask")
    assert "No fixed version" in flask_finding["remediation"]


def test_parse_pip_audit_json_handles_empty_payload():
    assert SupplyChainScanner().parse_pip_audit_json({}) == []
    assert SupplyChainScanner().parse_pip_audit_json({"dependencies": []}) == []


def test_scan_returns_empty_list_when_pip_audit_missing(monkeypatch):
    def _raise_not_found(*args, **kwargs):
        raise FileNotFoundError("pip-audit not found")

    monkeypatch.setattr("nexus.advanced.supply_chain.run_subprocess", _raise_not_found)
    assert SupplyChainScanner().scan("requirements.txt") == []
