import pytest

from nexus.compliance.frameworks import FRAMEWORKS
from nexus.compliance.reports import DISCLAIMER, generate_compliance_report

REQUIRED_DISCLAIMER_SENTENCE = (
    "This is NOT a certification, attestation, or audit report, and does not by itself "
    "establish compliance with"
)


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_report_generates_without_crashing_for_every_framework(framework):
    report = generate_compliance_report(framework)
    assert isinstance(report, str)
    assert len(report) > 0


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_report_contains_required_disclaimer(framework):
    report = generate_compliance_report(framework)
    assert REQUIRED_DISCLAIMER_SENTENCE in report
    assert "Consult a qualified compliance professional / auditor for actual certification." in report
    # Disclaimer must be prominent: present near the top and again at the end.
    top = report[:600]
    bottom = report[-600:]
    assert REQUIRED_DISCLAIMER_SENTENCE in top
    assert REQUIRED_DISCLAIMER_SENTENCE in bottom


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_report_contains_summary_table(framework):
    report = generate_compliance_report(framework)
    assert "| Status | Count |" in report
    assert "| Evidenced |" in report
    assert "| Partial |" in report
    assert "| Gap |" in report


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_report_lists_every_control_id(framework):
    from nexus.compliance.frameworks import get_mappings

    report = generate_compliance_report(framework)
    for mapping in get_mappings(framework):
        assert mapping.control.id in report


def test_report_rejects_unknown_framework():
    with pytest.raises(ValueError):
        generate_compliance_report("NOT_A_FRAMEWORK")


def test_disclaimer_template_mentions_framework_name():
    text = DISCLAIMER.format(framework="SOC2")
    assert "SOC2" in text
