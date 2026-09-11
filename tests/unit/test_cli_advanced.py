"""nexus/advanced/*.py (15 modules) and nexus/compliance/*.py (3 modules)
were real, tested code with zero way to actually run them — no CLI command,
no dashboard endpoint. `nexus advanced <cmd>` / `nexus compliance <cmd>` is
the fix. These tests exercise the CLI wiring, not the underlying modules'
own logic (which already has its own test suite)."""
import json

import pytest
from typer.testing import CliRunner

from nexus.cli import app

runner = CliRunner()


@pytest.fixture
def findings_file(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([
        {"title": "SQL injection", "severity": "critical", "tool": "webapp.sqli", "affected_asset": "example.com"},
        {"title": "Outdated jQuery", "severity": "medium", "tool": "appsec.dependency_analysis", "affected_asset": "example.com"},
    ]), encoding="utf-8")
    return path


def test_advanced_list_shows_all_15_modules():
    result = runner.invoke(app, ["advanced", "list"])
    assert result.exit_code == 0
    assert "threat_modeling" in result.output
    assert "deepfake_detection" in result.output


def test_advanced_attack_paths_runs_against_real_findings(findings_file):
    result = runner.invoke(app, ["advanced", "attack-paths", "--findings", str(findings_file)])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "risk_score" in data[0]


def test_advanced_triage_prioritizes_by_default(findings_file):
    result = runner.invoke(app, ["advanced", "triage", "--findings", str(findings_file)])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "priority_score" in data[0]


def test_advanced_triage_dedupe_flag(findings_file):
    result = runner.invoke(app, ["advanced", "triage", "--findings", str(findings_file), "--dedupe"])
    assert result.exit_code == 0


def test_advanced_pq_sign_and_verify_round_trip(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("real evidence content", encoding="utf-8")

    signed = runner.invoke(app, ["advanced", "pq-sign", str(evidence)])
    assert signed.exit_code == 0
    sig_path = tmp_path / "evidence.txt.sig"
    assert sig_path.exists()

    verified = runner.invoke(app, ["advanced", "pq-verify", str(evidence), str(sig_path)])
    assert verified.exit_code == 0
    assert "valid" in verified.output.lower()


def test_advanced_fuzz_runs_offline_ga(tmp_path):
    result = runner.invoke(app, ["advanced", "fuzz", "--seed", "admin", "--generations", "2", "--population-size", "6"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) > 0


def test_advanced_findings_file_must_be_a_list_or_findings_key(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not_findings": []}), encoding="utf-8")
    result = runner.invoke(app, ["advanced", "triage", "--findings", str(bad)])
    assert result.exit_code != 0


def test_compliance_frameworks_lists_all_six():
    result = runner.invoke(app, ["compliance", "frameworks"])
    assert result.exit_code == 0
    for fw in ("SOC2", "ISO27001", "NIST_CSF", "GDPR", "HIPAA", "PCI_DSS"):
        assert fw in result.output


def test_compliance_report_generates_a_real_disclaimed_report():
    result = runner.invoke(app, ["compliance", "report", "SOC2"])
    assert result.exit_code == 0
    assert "NOT a" in result.output or "not a" in result.output.lower()


def test_compliance_report_rejects_unknown_framework():
    result = runner.invoke(app, ["compliance", "report", "NOT_A_REAL_FRAMEWORK"])
    assert result.exit_code == 1


def test_compliance_report_writes_to_a_file(tmp_path):
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["compliance", "report", "GDPR", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "GDPR" in out.read_text(encoding="utf-8")
