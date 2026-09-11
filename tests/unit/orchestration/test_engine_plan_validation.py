"""Regression coverage for OrchestrationEngine's plan validation.

Real bug found in this session's audit: nothing validated an LLM-produced
mission plan before handing it to FlowController/DependencyGraph — a
hallucinated depends_on reference or a genuine dependency cycle raised an
uncaught GraphError all the way out of run_mission (crashing the entire
mission instead of degrading like every other stage in that method), and
two phases sharing the same id were silently collapsed into one by
TaskManager's `{t["id"]: t for t in plan}`, dropping a phase with no error
at all.
"""
import json
from unittest.mock import patch

import pytest

from nexus.orchestration.engine import OrchestrationEngine


def test_validate_plan_accepts_a_well_formed_plan():
    plan = [
        {"id": "P1", "agent": "recon_agent", "depends_on": []},
        {"id": "P2", "agent": "network_agent", "depends_on": ["P1"]},
    ]
    assert OrchestrationEngine._validate_plan(plan) is None


def test_validate_plan_rejects_duplicate_ids():
    plan = [
        {"id": "P1", "agent": "recon_agent", "depends_on": []},
        {"id": "P1", "agent": "network_agent", "depends_on": []},
    ]
    error = OrchestrationEngine._validate_plan(plan)
    assert error is not None
    assert "duplicate" in error


def test_validate_plan_rejects_unknown_dependency_reference():
    plan = [{"id": "P1", "agent": "recon_agent", "depends_on": ["P99"]}]
    error = OrchestrationEngine._validate_plan(plan)
    assert error is not None
    assert "P99" in error


def test_validate_plan_rejects_a_cycle():
    plan = [
        {"id": "P1", "agent": "recon_agent", "depends_on": ["P2"]},
        {"id": "P2", "agent": "network_agent", "depends_on": ["P1"]},
    ]
    error = OrchestrationEngine._validate_plan(plan)
    assert error is not None


@pytest.mark.asyncio
async def test_plan_mission_falls_back_to_default_plan_on_hallucinated_dependency(monkeypatch):
    """An LLM response that's valid JSON but references a nonexistent phase
    id used to reach DependencyGraph unvalidated and crash the mission;
    now it should fall back to the known-safe default plan instead."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    hallucinated = json.dumps([
        {"id": "P1", "agent": "recon_agent", "task": "recon", "domain": "reconnaissance", "depends_on": ["P404"]},
    ])
    with patch("nexus.intelligence.llm.router.LLMRouter.complete", return_value=hallucinated):
        engine = OrchestrationEngine(llm_provider="mock")
        plan = await engine._plan_mission("example.com", "guided", "quick_scan", "test-mission")

    # Fell back to the 5-phase default plan rather than the 1-phase hallucinated one.
    assert len(plan) == 5
    assert OrchestrationEngine._validate_plan(plan) is None


@pytest.mark.asyncio
async def test_plan_mission_falls_back_on_duplicate_ids(monkeypatch):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    duplicated = json.dumps([
        {"id": "P1", "agent": "recon_agent", "task": "a", "domain": "reconnaissance", "depends_on": []},
        {"id": "P1", "agent": "network_agent", "task": "b", "domain": "network", "depends_on": []},
    ])
    with patch("nexus.intelligence.llm.router.LLMRouter.complete", return_value=duplicated):
        engine = OrchestrationEngine(llm_provider="mock")
        plan = await engine._plan_mission("example.com", "guided", "quick_scan", "test-mission-2")

    assert len(plan) == 5  # default plan, not the 2-phase duplicate-id one


# ── HITL escalation wiring ────────────────────────────────────────────────
# debate_consensus_agent labels a disagreement-verdict finding
# `escalate_to: "hitl_liaison_agent"`, but nothing ever actually invoked
# that agent — the label was purely aspirational. _escalate_to_hitl wires
# it for real and persists the review queue where an operator can find it.

@pytest.mark.asyncio
async def test_escalate_to_hitl_persists_a_review_queue(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = OrchestrationEngine(llm_provider="mock")
    escalated = [
        {"id": "E-1", "title": "Ambiguous finding disputed by debate", "severity": "medium", "consensus": "disagreement"},
    ]

    summary = await engine._escalate_to_hitl("example.com", "test-hitl-mission", escalated)

    assert summary["review_items"] == 1
    assert summary["path"] is not None
    review_path = tmp_path / "engagements" / "test-hitl-mission" / "hitl_review.json"
    assert review_path.exists()
    import json as _json
    saved = _json.loads(review_path.read_text(encoding="utf-8"))
    assert saved["review_items"][0]["finding_id"] == "E-1"
    assert saved["review_summary"]["pending"] == 1


@pytest.mark.asyncio
async def test_escalate_to_hitl_no_op_when_nothing_escalated(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = OrchestrationEngine(llm_provider="mock")
    summary = await engine._escalate_to_hitl("example.com", "test-hitl-empty", [])
    assert summary == {"review_items": 0, "path": None}
    assert not (tmp_path / "engagements").exists()


# ── AttackChain decision-layer wiring ───────────────────────────────────────
# AttackChain.recommend_next (nexus/orchestration/decision/attack_chain.py)
# was built but never called anywhere in the live mission pipeline.

def test_recommend_next_domains_reflects_finding_domains():
    findings = [
        {"tool": "reconnaissance.dns_recon", "severity": "high"},
        {"tool": "reconnaissance.subdomain_enum", "severity": "medium"},
    ]
    recommendation = OrchestrationEngine._recommend_next_domains(findings)
    assert isinstance(recommendation, list)
    assert len(recommendation) > 0
    # reconnaissance findings should recommend network/webapp/cloud next,
    # per AttackChain's own _NEXT_DOMAIN table.
    assert any(d in recommendation for d in ("network", "webapp", "cloud"))


def test_recommend_next_domains_empty_findings_defaults_to_reconnaissance():
    assert OrchestrationEngine._recommend_next_domains([]) == ["reconnaissance"]
