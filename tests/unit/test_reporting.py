from nexus.reporting.generator import ReportGenerator
from nexus.reporting.exporters.csv_export import CsvExport
from nexus.reporting.exporters.html_export import HtmlExport
from nexus.reporting.exporters.json_export import JsonExport
from nexus.reporting.exporters.sarif_export import SarifExport
import json
import os
import tempfile
from pathlib import Path


def _make_tmpdir():
    """Create a temp dir inside the project to avoid Windows AppData permission issues."""
    d = Path(tempfile.mkdtemp(prefix="nexus_test_", dir=os.getcwd()))
    return d


def test_report_includes_assessment_context_and_severity_summary():
    tmp = _make_tmpdir()
    report = ReportGenerator().generate(
        [
            {"title": "TLS certificate expires soon", "severity": "high", "evidence": "certificate expires in 2 days"},
            {"title": "Connection succeeded", "severity": "info", "evidence": "reachable"},
        ],
        target="localhost",
        mission_id="test-mission",
        engagement={"client": "Example", "scope": ["localhost"], "authorization_reference": "TICKET-1"},
    )
    assert "0 critical, 1 high" in report
    assert "TLS certificate expires soon" in report
    output = ReportGenerator.write(report, tmp / "report.md")
    assert output.read_text(encoding="utf-8") == report


def test_portable_exporters_create_valid_artifacts():
    tmp = _make_tmpdir()
    findings = [{"severity": "high", "title": "<unsafe markup>", "evidence": "proof"}]
    JsonExport().export(findings, tmp / "findings.json")
    HtmlExport().export(findings, tmp / "findings.html")
    CsvExport().export(findings, tmp / "findings.csv")
    SarifExport().export(findings, tmp / "findings.sarif")
    assert json.loads((tmp / "findings.json").read_text())["findings"][0]["severity"] == "high"
    # HTML exporter escapes markup: <unsafe markup> becomes <unsafe markup>
    html_content = (tmp / "findings.html").read_text(encoding="utf-8")
    escaped = chr(38) + "lt;" + "unsafe markup" + chr(38) + "gt;"
    assert escaped in html_content
    # CSV uses Finding schema fields (title, evidence, remediation) — not "description"
    csv_content = (tmp / "findings.csv").read_text(encoding="utf-8")
    assert "title" in csv_content
    assert "evidence" in csv_content
    assert json.loads((tmp / "findings.sarif").read_text())["version"] == "2.1.0"