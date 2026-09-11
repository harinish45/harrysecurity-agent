from nexus.reporting.context import ReportBranding, ReportContext, ReportEngagement, ReportProvenance
from nexus.reporting.rendering import render_html


def test_white_label_report_html_contains_dynamic_branding_and_provenance():
    context = ReportContext(
        branding=ReportBranding(
            organization_name="Example Security",
            accent_color="#00aaff",
            footer_text="CLIENT CONFIDENTIAL",
            contact_email="security@example.test",
        ),
        engagement=ReportEngagement(client="Example Corp", engagement_id="ENG-1"),
        provenance=ReportProvenance("mission-1", platform_version="1.1", template_version="2"),
    )
    html = render_html("Security Assessment", context, (("Executive Summary", "Validated observations"),))
    assert "Example Security" in html
    assert "CLIENT CONFIDENTIAL" in html
    assert "security@example.test" in html
    assert "mission-1" in html
    assert "HARINISH" not in html


def test_render_html_escapes_section_content_against_injection():
    """A finding's title/evidence text can legitimately contain raw HTML/JS
    payloads (that's often what makes an XSS finding real) — render_html
    must never let that text execute when the report is opened in a
    browser. Unlike heading/branding fields, section `content` previously
    went straight into the `<div>` with no escaping at all."""
    context = ReportContext(
        branding=ReportBranding(
            organization_name="Example Security",
            accent_color="#00aaff",
            footer_text="CLIENT CONFIDENTIAL",
            contact_email="security@example.test",
        ),
        engagement=ReportEngagement(client="Example Corp", engagement_id="ENG-1"),
        provenance=ReportProvenance("mission-1", platform_version="1.1", template_version="2"),
    )
    payload = "<script>alert(1)</script>"
    html = render_html("Security Assessment", context, (("Finding", payload),))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
