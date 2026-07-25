from nexus.reporting.generator import ReportGenerator
from nexus.reporting.exporters.csv_export import CsvExport
from nexus.reporting.exporters.html_export import HtmlExport
from nexus.reporting.exporters.json_export import JsonExport
from nexus.reporting.exporters.sarif_export import SarifExport
import json


def test_report_includes_assessment_context_and_severity_summary(tmp_path):
    report = ReportGenerator().generate(
        [
            {"title": "TLS certificate expires soon", "severity": "high", "evidence": "certificate expires in 2 days"},
            {"title": "Connection succeeded", "severity": "info", "evidence": "reachable"},
        ],
        target="localhost",
        mission_id="test-mission",
        engagement={"client": "Example", "scope": ["localhost"], "authorization_reference": "TICKET-1"},
    )
    assert "Critical: 0; High: 1" in report
    assert "TLS certificate expires soon" in report
    output = ReportGenerator.write(report, tmp_path / "report.md")
    assert output.read_text(encoding="utf-8") == report


def test_portable_exporters_create_valid_artifacts(tmp_path):
    findings = [{"severity": "high", "title": "<unsafe markup>", "evidence": "proof"}]
    JsonExport().export(findings, tmp_path / "findings.json")
    HtmlExport().export(findings, tmp_path / "findings.html")
    CsvExport().export(findings, tmp_path / "findings.csv")
    SarifExport().export(findings, tmp_path / "findings.sarif")
    assert json.loads((tmp_path / "findings.json").read_text())["findings"][0]["severity"] == "high"
    assert "&lt;unsafe markup&gt;" in (tmp_path / "findings.html").read_text(encoding="utf-8")
    assert "description" in (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "findings.sarif").read_text())["version"] == "2.1.0"
