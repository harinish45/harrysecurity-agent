import json

from nexus.reporting.professional import ReportBranding, render_html, render_pdf


def sample_report():
    return {
        "_meta": {
            "target": "127.0.0.1",
            "authorization_reference": "AUTH-TEST",
            "generated_at": "2026-08-17T08:00:00Z",
        },
        "open_ports": [22, 8080],
        "findings": [
            {
                "title": "Exposed development service",
                "severity": "high",
                "asset": "127.0.0.1",
                "tool": "network.port_scan",
                "confidence": "high",
                "evidence": "tcp/8080 open",
                "description": "A development service is externally reachable.",
                "impact": "May expose administrative functionality.",
                "remediation": "Restrict the service and harden access controls.",
            }
        ],
    }


def test_professional_html_is_white_label_and_escapes_content():
    data = sample_report()
    data["findings"][0]["title"] = '<script>alert(1)</script>'
    html = render_html(data, ReportBranding(organization_name="Example Security", logo_text="ES"))
    assert "Example Security" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "alert(1)</script>" not in html
    assert "Executive summary" in html
    assert "Remediation roadmap" in html


def test_professional_pdf_is_generated(tmp_path):
    output = tmp_path / "assessment.pdf"
    result = render_pdf(sample_report(), output)
    assert result == output
    assert output.exists()
    assert output.read_bytes()[:4] == b"%PDF"
