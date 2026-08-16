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
