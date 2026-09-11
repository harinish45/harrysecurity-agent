from nexus.orchestration.handoff.context_transfer import ContextTransfer
from nexus.orchestration.handoff.handoff_manager import HandoffManager


def test_context_transfer_collects_findings_assets_and_domains():
    results = [
        {
            "agent": "recon_agent",
            "domain": "reconnaissance",
            "findings": [{"title": "Open port 22", "affected_asset": "10.0.0.5"}],
        },
        {
            "agent": "network_agent",
            "findings": ["Plain string finding"],
        },
    ]
    context = ContextTransfer.package(results)

    assert "Open port 22" in context["prior_findings"]
    assert "Plain string finding" in context["prior_findings"]
    assert "10.0.0.5" in context["discovered_assets"]
    assert "reconnaissance" in context["completed_domains"]
    assert "network" in context["completed_domains"]


def test_context_transfer_handles_empty_results():
    context = ContextTransfer.package([])
    assert context == {"prior_findings": [], "discovered_assets": [], "completed_domains": []}


def test_handoff_manager_flags_critical_and_high_findings_for_escalation():
    results = [
        {
            "agent": "vuln_analyst_agent",
            "findings": [
                {"title": "RCE in login form", "severity": "critical"},
                {"title": "Minor info leak", "severity": "low"},
            ],
        }
    ]
    context = HandoffManager.prepare_next_batch(results)

    escalated_titles = [e["title"] for e in context["escalations"]]
    assert "RCE in login form" in escalated_titles
    assert "Minor info leak" not in escalated_titles


def test_handoff_manager_with_no_findings_has_no_escalations():
    context = HandoffManager.prepare_next_batch([])
    assert context["escalations"] == []
