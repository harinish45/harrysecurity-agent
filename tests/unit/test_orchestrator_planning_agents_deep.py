"""Behavioral coverage for 4 orchestrator/defensive-tier agents with
unique (non-templated) logic, not covered by the generic dispatch-pattern
tests in test_agents_deep_coverage.py:

- MissionCommanderAgent / TaskPlannerAgent: real 3-tool recon dispatch
  plus a static phase/task-dependency plan.
- QualityAssessorAgent: real severity x confidence risk-score arithmetic,
  plus 2 real tool_registry.run() calls for scoring/prioritization.
- ContinuousAsmAgent: real snapshot diffing against a JSON file on disk —
  first-run baseline, added/removed delta detection, error-tolerant
  per-tool collection.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from nexus.agents.defensive.continuous_asm_agent import ContinuousAsmAgent
from nexus.agents.orchestrator.mission_commander_agent import MissionCommanderAgent
from nexus.agents.orchestrator.quality_assessor_agent import QualityAssessorAgent
from nexus.agents.orchestrator.task_planner_agent import TaskPlannerAgent
from nexus.agents.support.validator_agent import ValidatorAgent
from nexus.tools.registry import tool_registry


def _run(agent, **kwargs):
    return asyncio.run(agent.run("plan", **kwargs))


# ── MissionCommanderAgent ────────────────────────────────────────────────

def test_mission_commander_dispatches_recon_and_builds_four_phases():
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        result = _run(MissionCommanderAgent(), target="example.com")

    assert result["status"] == "completed"
    assert mock_run.call_count == 3
    assert result["metadata"]["total_phases"] == 4
    phase_names = [p["name"] for p in result["metadata"]["phases"]]
    assert phase_names == ["Reconnaissance", "Vulnerability Assessment", "Exploitation", "Reporting"]


def test_mission_commander_no_target_fails_cleanly():
    result = _run(MissionCommanderAgent(), target="")
    assert result["status"] == "failed"


def test_mission_commander_survives_recon_tool_failure():
    with patch.object(tool_registry, "run", side_effect=RuntimeError("dns down")):
        result = _run(MissionCommanderAgent(), target="example.com")
    assert result["status"] == "completed"
    assert len(result["findings"]) == 3
    assert all("dns down" in f["title"] for f in result["findings"])


# ── TaskPlannerAgent ──────────────────────────────────────────────────────

def test_task_planner_builds_six_dependency_ordered_tasks():
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        result = _run(TaskPlannerAgent(), target="example.com")

    assert result["status"] == "completed"
    tasks = result["metadata"]["tasks"]
    assert result["metadata"]["total_tasks"] == 6
    assert [t["id"] for t in tasks] == ["T1", "T2", "T3", "T4", "T5", "T6"]
    # T4 (vuln scanning) depends on both recon tasks — real dependency structure.
    assert tasks[3]["depends_on"] == ["T2", "T3"]


def test_task_planner_no_target_fails_cleanly():
    result = _run(TaskPlannerAgent(), target="")
    assert result["status"] == "failed"


# ── QualityAssessorAgent ─────────────────────────────────────────────────

def test_quality_assessor_no_findings_short_circuits():
    result = _run(QualityAssessorAgent(), target="example.com", findings=[])
    assert result["status"] == "no_findings"


def test_quality_assessor_computes_real_risk_score_and_validation_status():
    findings = [
        {"id": "F-1", "title": "SQLi", "severity": "critical", "confidence": "certain"},   # weight = 10*1.0 = 10
        {"id": "F-2", "title": "Info leak", "severity": "info", "confidence": "low"},        # weight = 0*0.3 = 0
    ]
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        result = _run(QualityAssessorAgent(), target="example.com", findings=findings)

    assert result["status"] == "completed"
    assert mock_run.call_count == 2  # risk_scoring + prioritization
    validated = result["metadata"]["validated_findings"]
    f1 = next(v for v in validated if v["id"] == "F-1")
    f2 = next(v for v in validated if v["id"] == "F-2")
    assert f1["risk_score"] == 10.0
    assert f1["validation_status"] == "validated"  # weight >= 3.0
    assert f2["risk_score"] == 0.0
    assert f2["validation_status"] == "review"  # weight < 3.0
    # overall_risk = (10 + 0) / (2 findings * 10) * 10 = 5.0
    assert result["metadata"]["overall_risk_score"] == 5.0
    assert result["metadata"]["severity_counts"]["critical"] == 1
    assert result["metadata"]["severity_counts"]["info"] == 1


def test_quality_assessor_survives_scoring_tool_failure():
    findings = [{"id": "F-1", "title": "X", "severity": "high", "confidence": "medium"}]
    with patch.object(tool_registry, "run", side_effect=RuntimeError("scoring service down")):
        result = _run(QualityAssessorAgent(), target="example.com", findings=findings)
    assert result["status"] == "completed"
    error_entries = [v for v in result["metadata"]["validated_findings"] if "error" in v.get("title", "").lower()]
    assert len(error_entries) == 2  # both risk_scoring and prioritization failed


# ── ContinuousAsmAgent ────────────────────────────────────────────────────

def test_continuous_asm_no_target_returns_no_findings_not_failed():
    result = _run(ContinuousAsmAgent(), target="")
    assert result["status"] == "no_findings"


def test_continuous_asm_first_run_has_no_deltas_but_saves_snapshot(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "completed", "findings": [{"title": "subdomain: api.example.com"}]}
        result = _run(ContinuousAsmAgent(), target="example.com")

    assert result["status"] == "no_findings"  # nothing to diff against on the first run
    snapshot_path = Path("engagements") / "example.com" / "asm" / "last.json"
    assert snapshot_path.exists()
    saved = json.loads(snapshot_path.read_text())
    assert saved["target"] == "example.com"
    assert len(saved["items"]) == 4  # one per _RECON_TOOLS entry


def test_continuous_asm_second_run_detects_added_and_removed_items(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    snapshot_path = Path("engagements") / "example.com" / "asm" / "last.json"
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps({
        "target": "example.com",
        "items": ["reconnaissance.dns_recon: old-item", "reconnaissance.subdomain_enum: gone.example.com"],
        "collected_at": "2026-01-01T00:00:00+00:00",
    }))

    def fake_run(tool_name, target=None, **kwargs):
        if tool_name == "reconnaissance.dns_recon":
            return {"status": "completed", "findings": [{"title": "new-item"}]}
        return {"status": "no_findings", "findings": []}

    with patch.object(tool_registry, "run", side_effect=fake_run):
        result = _run(ContinuousAsmAgent(), target="example.com")

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("New attack-surface item" in t and "new-item" in t for t in titles)
    assert any("no longer observed" in t and "old-item" in t for t in titles)
    assert any("no longer observed" in t and "gone.example.com" in t for t in titles)


def test_continuous_asm_survives_corrupt_snapshot_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    snapshot_path = Path("engagements") / "example.com" / "asm" / "last.json"
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text("{not valid json")

    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        result = _run(ContinuousAsmAgent(), target="example.com")

    # A corrupt snapshot degrades to "treat as first run", not a crash.
    assert result["status"] == "no_findings"


def test_continuous_asm_sanitizes_target_for_filesystem_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        _run(ContinuousAsmAgent(), target="http://weird:target/path?q=1")

    # Unsafe path characters must be stripped, not passed through to Path().
    matches = list(Path("engagements").glob("*/asm/last.json"))
    assert len(matches) == 1
    assert "/" not in matches[0].parent.parent.name
    assert ":" not in matches[0].parent.parent.name


# ── ValidatorAgent ────────────────────────────────────────────────────────

def test_validator_dispatches_six_tools_and_counts_pass_fail():
    def fake_run(tool_name, target=None, **kwargs):
        if tool_name == "compliance.security_audits":
            return {"status": "completed", "findings": [{"title": "Weak policy", "severity": "high"}]}
        return {"status": "completed", "findings": [{"title": "OK", "severity": "info"}]}

    with patch.object(tool_registry, "run", side_effect=fake_run) as mock_run:
        result = _run(ValidatorAgent(), target="example.com", findings=[{"title": "F1"}])

    assert result["status"] == "completed"
    assert mock_run.call_count == 6
    assert result["metadata"]["passed_checks"] == 5
    assert result["metadata"]["failed_checks"] == 1


def test_validator_no_target_fails_cleanly():
    result = _run(ValidatorAgent(), target="")
    assert result["status"] == "failed"


def test_validator_reports_remediation_verified_when_status_provided():
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        result = _run(ValidatorAgent(), target="example.com", remediation_status={"F1": "fixed"})
    assert result["metadata"]["remediation_verified"] is True
    # remediation_status must actually reach the remediation_validation tool call.
    last_call = mock_run.call_args_list[-1]
    assert last_call.kwargs["remediation_status"] == {"F1": "fixed"}
