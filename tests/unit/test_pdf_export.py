"""Real bug confirmed by this session's audit: PdfExport().export() raised
RuntimeError('No PDF rendering backend available') on any host without
weasyprint's native GTK libs, a working Playwright/Chromium install, or the
wkhtmltopdf binary on PATH — which is most hosts, including this dev
environment. Fixed by adding a pure-Python xhtml2pdf fallback (no native/
system dependencies) with a print-safe CSS swap, since xhtml2pdf's
reportlab-based CSS parser can't handle html_export.py's :not()/@media/
custom-property/flexbox-heavy stylesheet.
"""
from pathlib import Path

from nexus.reporting.exporters.pdf_export import PdfExport

_FINDINGS = [
    {
        "id": "F-1", "title": "SQLi in login form", "severity": "critical",
        "affected_asset": "host-a", "tool": "webapp.sqli_scan",
        "verification_status": "verified",
        "mitre_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        "business_impact": "payments-adjacent", "evidence": "' OR 1=1--",
    },
    {
        "id": "F-2", "title": "Weak TLS config", "severity": "medium",
        "affected_asset": "host-b", "tool": "network.tls_testing",
        "verification_status": "unverified",
    },
    {
        "id": "CHAIN-001", "title": "Attack chain: host-a -> host-b", "severity": "high",
        "affected_asset": "host-a", "kind": "synthetic_chain",
        "chain_assets": ["host-a", "host-b"],
    },
]


def test_pdf_export_produces_real_pdf(tmp_path):
    out = tmp_path / "report.pdf"
    result_path = PdfExport().export(_FINDINGS, out, title="Test Report", redact=False)

    assert result_path == out
    assert out.exists()
    data = out.read_bytes()
    assert data[:4] == b"%PDF", "output is not a real PDF (magic bytes missing)"
    assert len(data) > 1024, f"PDF suspiciously small ({len(data)} bytes) — likely a near-empty/broken render"


def test_pdf_export_handles_zero_findings(tmp_path):
    out = tmp_path / "empty_report.pdf"
    result_path = PdfExport().export([], out, title="Empty Report", redact=False)
    data = result_path.read_bytes()
    assert data[:4] == b"%PDF"


def test_xhtml2pdf_fallback_used_when_other_backends_unavailable(tmp_path, monkeypatch):
    """Confirm the new fallback actually fires (not vacuously skipped)
    when the higher-priority backends are unavailable -- forces the
    exact failure mode this session hit on a fresh Windows host."""
    monkeypatch.setattr(PdfExport, "_try_weasyprint", staticmethod(lambda html, output: False))
    monkeypatch.setattr(PdfExport, "_try_playwright", staticmethod(lambda html_path, output: False))
    monkeypatch.setattr(PdfExport, "_try_edge_or_chrome", staticmethod(lambda html_path, output: False))
    monkeypatch.setattr(PdfExport, "_try_wkhtmltopdf", staticmethod(lambda html_path, output: False))

    out = tmp_path / "fallback_report.pdf"
    result_path = PdfExport().export(_FINDINGS, out, title="Fallback Test", redact=False)
    data = result_path.read_bytes()
    assert data[:4] == b"%PDF"


def test_pdf_export_raises_clearly_when_all_backends_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(PdfExport, "_try_weasyprint", staticmethod(lambda html, output: False))
    monkeypatch.setattr(PdfExport, "_try_playwright", staticmethod(lambda html_path, output: False))
    monkeypatch.setattr(PdfExport, "_try_edge_or_chrome", staticmethod(lambda html_path, output: False))
    monkeypatch.setattr(PdfExport, "_try_wkhtmltopdf", staticmethod(lambda html_path, output: False))
    monkeypatch.setattr(PdfExport, "_try_xhtml2pdf", classmethod(lambda cls, html, output: False))

    out = tmp_path / "unreachable.pdf"
    try:
        PdfExport().export(_FINDINGS, out, title="Should Fail", redact=False)
        assert False, "expected RuntimeError when every backend fails"
    except RuntimeError as exc:
        assert "No PDF rendering backend available" in str(exc)
