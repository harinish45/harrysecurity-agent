from nexus.reporting.generator import ReportGenerator
from nexus.reporting.exporters.csv_export import CsvExport
from nexus.reporting.exporters.html_export import HtmlExport
from nexus.reporting.exporters.json_export import JsonExport
from nexus.reporting.exporters.sarif_export import SarifExport
from nexus.reporting.exporters.pdf_export import PdfExport
from nexus.foundation.schema import redact_findings
from nexus.foundation.paths import safe_slug
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


# ── redaction ─────────────────────────────────────────────────────────────

def test_redact_findings_strips_secrets_but_keeps_other_fields():
    findings = [{
        "id": "F-001",
        "title": "Leaked credentials in response",
        "severity": "high",
        "evidence": "password=hunter2 and api_key: sk-abc123xyz",
        "remediation": "Rotate the exposed credentials.",
    }]
    redacted = redact_findings(findings)
    evidence = redacted[0]["evidence"]
    assert "hunter2" not in evidence
    assert "sk-abc123xyz" not in evidence
    assert "[REDACTED]" in evidence
    # Round-trips everything else untouched.
    assert redacted[0]["title"] == "Leaked credentials in response"
    assert redacted[0]["severity"] == "high"
    assert redacted[0]["remediation"] == "Rotate the exposed credentials."
    assert redacted[0]["id"] == "F-001"


def test_redact_findings_handles_aws_key_pem_and_bearer_token():
    findings = [{
        "evidence": (
            "AKIAABCDEFGHIJKLMNOP leaked; "
            "Authorization: Bearer abcDEF123.456-xyz_ok; "
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAKC\n-----END RSA PRIVATE KEY-----"
        ),
    }]
    redacted = redact_findings(findings)[0]["evidence"]
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted
    assert "abcDEF123.456-xyz_ok" not in redacted
    assert "MIIBogIBAAKC" not in redacted


# ── exporter redaction wiring (default on, opt-out) ─────────────────────────

def test_csv_export_redacts_by_default_and_opt_out():
    tmp = _make_tmpdir()
    findings = [{"severity": "high", "title": "leak", "affected_asset": "host1",
                 "evidence": "token=supersecrettoken123"}]
    CsvExport().export(findings, tmp / "r.csv")
    assert "supersecrettoken123" not in (tmp / "r.csv").read_text(encoding="utf-8")
    CsvExport().export(findings, tmp / "r2.csv", redact=False)
    assert "supersecrettoken123" in (tmp / "r2.csv").read_text(encoding="utf-8")


def test_json_export_redacts_by_default_and_opt_out():
    tmp = _make_tmpdir()
    findings = [{"severity": "high", "title": "leak", "evidence": "secret: topsecretvalue999"}]
    JsonExport().export(findings, tmp / "r.json")
    assert "topsecretvalue999" not in (tmp / "r.json").read_text(encoding="utf-8")
    JsonExport().export(findings, tmp / "r2.json", redact=False)
    assert "topsecretvalue999" in (tmp / "r2.json").read_text(encoding="utf-8")


def test_html_export_redacts_by_default_and_opt_out():
    tmp = _make_tmpdir()
    findings = [{"severity": "high", "title": "leak", "evidence": "password=hunter2plainsecret"}]
    HtmlExport().export(findings, tmp / "r.html")
    assert "hunter2plainsecret" not in (tmp / "r.html").read_text(encoding="utf-8")
    HtmlExport().export(findings, tmp / "r2.html", redact=False)
    assert "hunter2plainsecret" in (tmp / "r2.html").read_text(encoding="utf-8")


def test_sarif_export_redacts_by_default_and_opt_out():
    tmp = _make_tmpdir()
    findings = [{"severity": "high", "title": "leak", "evidence": "Bearer abcDEF123456xyz"}]
    SarifExport().export(findings, tmp / "r.sarif")
    assert "abcDEF123456xyz" not in (tmp / "r.sarif").read_text(encoding="utf-8")
    SarifExport().export(findings, tmp / "r2.sarif", redact=False)
    assert "abcDEF123456xyz" in (tmp / "r2.sarif").read_text(encoding="utf-8")


def test_pdf_export_redacts_via_html_sidecar_and_opt_out():
    # No PDF rendering backend (weasyprint/playwright/wkhtmltopdf) is
    # guaranteed to be installed in the test environment, so PdfExport.export
    # may raise RuntimeError after all backends fail — but it always writes
    # the intermediate HTML sidecar first, which is what carries the
    # redaction wiring we're testing here.
    tmp = _make_tmpdir()
    findings = [{"severity": "high", "title": "leak", "evidence": "password=hunter2secretpdf"}]

    out = tmp / "findings.pdf"
    try:
        PdfExport().export(findings, out)
    except RuntimeError:
        pass
    html_sidecar = out.with_suffix(".html")
    assert html_sidecar.exists()
    assert "hunter2secretpdf" not in html_sidecar.read_text(encoding="utf-8")

    out2 = tmp / "findings_noredact.pdf"
    try:
        PdfExport().export(findings, out2, redact=False)
    except RuntimeError:
        pass
    html_sidecar2 = out2.with_suffix(".html")
    assert html_sidecar2.exists()
    assert "hunter2secretpdf" in html_sidecar2.read_text(encoding="utf-8")


# ── visualizations ───────────────────────────────────────────────────────

def _viz_findings():
    return [
        {"affected_asset": "host1.example.com", "tool": "network.port_scan",
         "severity": "critical", "evidence": "password=supersecretplanted1",
         "timestamp": "2024-01-01T00:00:00Z"},
        {"affected_asset": "host2.example.com", "tool": "network.vuln_scan",
         "severity": "high", "evidence": "clean evidence line",
         "timestamp": "2024-01-02T12:30:00Z"},
        {"affected_asset": "host3.example.com", "tool": "web.sql_injection",
         "severity": "low", "evidence": "another clean line",
         "timestamp": "2024-01-03T06:00:00Z"},
    ]


def test_attack_graph_viz_empty_and_nonempty():
    from nexus.reporting.visualizations.attack_graph_viz import AttackGraphViz
    viz = AttackGraphViz()

    empty_svg = viz.render([])
    assert "<svg" in empty_svg

    svg = viz.render(_viz_findings())
    assert "<svg" in svg
    assert "supersecretplanted1" not in svg


def test_risk_heatmap_empty_and_nonempty():
    from nexus.reporting.visualizations.risk_heatmap import RiskHeatmap
    viz = RiskHeatmap()

    empty_svg = viz.render([])
    assert "<svg" in empty_svg

    svg = viz.render(_viz_findings())
    assert "<svg" in svg
    assert "supersecretplanted1" not in svg


def test_timeline_viz_empty_and_nonempty():
    from nexus.reporting.visualizations.timeline_viz import TimelineViz
    viz = TimelineViz()

    empty_svg = viz.render([])
    assert "<svg" in empty_svg

    svg = viz.render(_viz_findings())
    assert "<svg" in svg
    assert "supersecretplanted1" not in svg


# ── path traversal regression (nexus_report.py slug logic) ─────────────────

def test_safe_slug_neutralizes_path_traversal_input():
    slug = safe_slug("../../etc/passwd")
    assert "/" not in slug
    assert "\\" not in slug
    assert ".." not in slug