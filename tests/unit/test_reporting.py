from nexus.reporting.generator import ReportGenerator
from nexus.reporting.exporters.csv_export import CsvExport
from nexus.reporting.exporters.html_export import HtmlExport
from nexus.reporting.exporters.json_export import JsonExport
from nexus.reporting.exporters.sarif_export import SarifExport
from nexus.reporting.exporters.pdf_export import PdfExport
from nexus.foundation.schema import redact_findings
from nexus.foundation.paths import safe_slug
import atexit
import json
import os
import re
import shutil
import tempfile
from pathlib import Path


def _make_tmpdir():
    """Create a temp dir inside the project to avoid Windows AppData permission
    issues. Registered for best-effort cleanup at interpreter exit rather than
    per-test teardown, since callers use it as a plain helper (not a fixture)
    across 9 call sites — this at least stops it from leaving nexus_test_*
    directories behind after every test run (296 had accumulated in the repo
    root before this fix)."""
    d = Path(tempfile.mkdtemp(prefix="nexus_test_", dir=os.getcwd()))
    atexit.register(shutil.rmtree, d, ignore_errors=True)
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


def test_report_never_renders_a_blank_finding_id():
    """Regression test: Finding.id used to default to "" for the common case
    (a plain dict finding, no explicit id) — every finding section header
    rendered as "###  — CRITICAL" (double space, id missing) and every
    remediation-table row had a blank Finding ID column."""
    report = ReportGenerator().generate(
        [{"title": "SQL injection in login form", "severity": "critical"}],
        target="example.com",
        mission_id="test-mission-ids",
    )
    assert "###  —" not in report
    assert "### F-" in report
    # The remediation table's Finding ID column must not be blank either.
    table_row = next(line for line in report.splitlines() if "SQL injection in login form" in line and line.startswith("|"))
    assert "| P1 | F-" in table_row


def test_finding_normalizes_none_or_non_string_severity_and_confidence_instead_of_crashing():
    """Regression test: Finding.__post_init__ called self.severity.lower()
    unconditionally — a finding with severity=None (a check that failed to
    classify) or a non-string severity crashed every exporter/report that
    funnels findings through normalize_findings()/Finding()."""
    from nexus.foundation.schema import normalize_findings

    result = normalize_findings([
        {"title": "unclassified check", "severity": None, "confidence": None},
        {"title": "bad type", "severity": 5, "confidence": 5},
    ])
    assert result[0]["severity"] == "info"
    assert result[0]["confidence"] == "medium"
    assert result[1]["severity"] == "info"
    assert result[1]["confidence"] == "medium"


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


def test_html_export_escapes_verification_status_in_class_attribute_and_text():
    """Regression test: verification_status was interpolated into the
    badge-{verification} class attribute and into element text without
    html.escape(), unlike every other field in the same row. Not exploitable
    today because verification_agent only ever emits 5 hardcoded literals,
    but if that value space ever grows to include finding-derived text this
    would be a quote-attribute-breakout XSS. Assert the sink escapes both
    the attribute and the text context."""
    tmp = _make_tmpdir()
    findings = [{
        "id": "F-1", "title": "SQLi", "severity": "high",
        "verification_status": '"><script>alert(1)</script>',
        "verification_detail": '"><script>alert(2)</script>',
    }]
    HtmlExport().export(findings, tmp / "verify.html")
    html_content = (tmp / "verify.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_content
    assert "<script>alert(2)</script>" not in html_content
    assert '"><script>' not in html_content


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


def test_sarif_export_includes_agent_enrichment_fields():
    """verification_status, mitre_techniques, business_impact, and
    chain_assets/kind (populated by the post-processing agents) used to be
    silently dropped by the SARIF exporter — a SARIF consumer saw strictly
    less annotation than the HTML/Markdown reports for the same mission,
    and synthetic_chain findings were indistinguishable from ordinary ones.
    Confirmed via this session's audit and fixed."""
    tmp = _make_tmpdir()
    findings = [
        {
            "severity": "high",
            "title": "cred reuse unlocks db host",
            "verification_status": "verified",
            "verification_detail": "confirmed via replay",
            "business_impact": "full database compromise",
            "mitre_techniques": [{"id": "T1078", "name": "Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078/"}],
            "kind": "synthetic_chain",
            "chain_assets": ["10.0.0.1", "10.0.0.2:5432"],
        }
    ]
    out = SarifExport().export(findings, tmp / "enriched.sarif")
    doc = json.loads(out.read_text(encoding="utf-8"))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["verificationStatus"] == "verified"
    assert props["verificationDetail"] == "confirmed via replay"
    assert props["businessImpact"] == "full database compromise"
    assert props["mitreTechniques"][0]["id"] == "T1078"
    assert props["kind"] == "synthetic_chain"
    assert props["chainAssets"] == ["10.0.0.1", "10.0.0.2:5432"]


def test_sarif_export_agent_enrichment_fields_default_when_absent():
    """A finding with no agent-added fields should still export cleanly,
    with the new properties present but empty rather than missing/crashing."""
    tmp = _make_tmpdir()
    findings = [{"severity": "low", "title": "plain finding"}]
    out = SarifExport().export(findings, tmp / "plain.sarif")
    doc = json.loads(out.read_text(encoding="utf-8"))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["verificationStatus"] == ""
    assert props["businessImpact"] == ""
    assert props["mitreTechniques"] == []
    assert props["kind"] == ""
    assert props["chainAssets"] == []


def test_sarif_artifact_location_is_a_well_formed_uri_for_bare_host_port():
    """affected_asset is often a bare "host:port" ("10.0.0.1:22"), not a
    valid SARIF 2.1.0 artifactLocation.uri — some strict SARIF consumers
    reject it. Confirmed via this session's audit and fixed."""
    tmp = _make_tmpdir()
    findings = [{"severity": "medium", "title": "open port", "affected_asset": "10.0.0.1:22"}]
    out = SarifExport().export(findings, tmp / "r.sarif")
    doc = json.loads(out.read_text(encoding="utf-8"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", uri), f"not a well-formed URI: {uri!r}"
    assert uri == "asset://10.0.0.1:22"


def test_sarif_artifact_location_passes_through_an_existing_scheme():
    tmp = _make_tmpdir()
    findings = [{"severity": "medium", "title": "x", "affected_asset": "https://example.com/path"}]
    out = SarifExport().export(findings, tmp / "r.sarif")
    doc = json.loads(out.read_text(encoding="utf-8"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://example.com/path"


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


# ── section numbering regression ────────────────────────────────────────
# Sections 4 (asset inventory)/6 (verification)/7 (MITRE)/8 (attack chains)
# only appear when there's data for them; they used to be hardcoded literal
# "## N." headings, so skipping one left a gap in the visible numbering
# (e.g. "## 5." straight to "## 7." with no "## 6."). Confirmed via this
# session's audit and fixed with a running counter instead.

def _section_numbers(report: str) -> list[int]:
    import re
    return [int(n) for n in re.findall(r"^## (\d+)\.", report, re.MULTILINE)]


def test_section_numbers_are_contiguous_with_no_findings():
    report = ReportGenerator().generate([], target="x", mission_id="m")
    numbers = _section_numbers(report)
    assert numbers == list(range(1, len(numbers) + 1))


def test_section_numbers_are_contiguous_with_every_optional_section_present():
    findings = [{
        "id": "F-1", "title": "SQLi", "severity": "critical", "affected_asset": "host-a",
        "tool": "webapp.sqli_scan", "verification_status": "verified",
        "mitre_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        "kind": "synthetic_chain", "chain_assets": ["host-a", "host-b"],
    }]
    report = ReportGenerator().generate(findings, target="x", mission_id="m")
    numbers = _section_numbers(report)
    assert numbers == list(range(1, len(numbers) + 1))
    # All optional sections actually rendered, not just skipped-and-still-contiguous.
    assert len(numbers) == 11


# ── HTML-escaping regression (chain_assets / business_impact / MITRE tags) ─
# chain_assets, business_impact, and MITRE id/name/url were embedded into the
# .md report with no escaping. An affected_asset (or other attacker-
# influenced field) of "<script>alert(1)</script>" would survive verbatim
# into the report and execute if the .md is ever opened in an HTML-capable
# Markdown viewer.

def test_attack_chain_assets_are_html_escaped_in_report():
    findings = [{
        "id": "F-1", "title": "chain", "severity": "critical",
        "kind": "synthetic_chain", "chain_assets": ["<script>alert(1)</script>", "host-b"],
    }]
    report = ReportGenerator().generate(findings, target="x", mission_id="m")
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report


def test_business_impact_is_html_escaped_in_report():
    findings = [{
        "id": "F-1", "title": "finding", "severity": "high",
        "business_impact": "<img src=x onerror=alert(1)>",
    }]
    report = ReportGenerator().generate(findings, target="x", mission_id="m")
    assert "<img src=x onerror=alert(1)>" not in report
    assert "&lt;img src=x onerror=alert(1)&gt;" in report


def test_mitre_technique_fields_are_html_escaped_in_report():
    findings = [{
        "id": "F-1", "title": "finding", "severity": "medium",
        "mitre_techniques": [{
            "id": "<b>T1190</b>",
            "name": "<script>alert(2)</script>",
            "url": "javascript:alert(3)\"><script>x</script>",
        }],
    }]
    report = ReportGenerator().generate(findings, target="x", mission_id="m")
    assert "<script>alert(2)</script>" not in report
    assert "<b>T1190</b>" not in report
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in report
    assert "&lt;b&gt;T1190&lt;/b&gt;" in report


# ── path traversal regression (nexus_report.py slug logic) ─────────────────

def test_safe_slug_neutralizes_path_traversal_input():
    slug = safe_slug("../../etc/passwd")
    assert "/" not in slug
    assert "\\" not in slug
    assert ".." not in slug