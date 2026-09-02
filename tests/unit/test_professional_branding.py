from pathlib import Path


def test_professional_console_has_no_personal_branding():
    html = Path("web/static/pro-console.html").read_text(encoding="utf-8")
    assert "HARINISH" not in html
    assert "harinish45" not in html


def test_report_renderer_has_no_personal_identifier_defaults():
    source = Path("nexus/reporting/professional.py").read_text(encoding="utf-8")
    assert "HARINISH" not in source
    assert "harinish45" not in source
