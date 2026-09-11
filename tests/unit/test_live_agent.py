"""scripts/live_agent.py is the actual code the dashboard's "start scan"
button runs (web/server.py spawns `nexus live` as a subprocess) — it used to
have zero guardrail enforcement of its own: no ScopeGuard/LegalGuard at the
top of run_assessment(), and its SQL-injection phase imported the sqli tool
directly instead of going through tool_registry.run(), skipping
RateGuard/EscalationGuard/AuditGuard for an active exploit-adjacent probe."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import live_agent  # noqa: E402

from nexus.foundation.config import config


@pytest.fixture(autouse=True)
def _pinned_scope(monkeypatch):
    """Pin the allow-list explicitly rather than relying on this machine's
    .env — a real NEXUS_ALLOWED_TARGETS can (and on this machine, does)
    include a wide-open CIDR for manual testing, which must not make a
    "blocked" assertion here silently pass through to a live scan of a real
    IP address."""
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")


def test_run_assessment_blocked_without_legal_ack(monkeypatch):
    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)
    result = live_agent.run_assessment("127.0.0.1", "127.0.0.1")

    assert result["_meta"]["status"] == "blocked"
    assert result["findings"] == []
    assert result["phases"] == []


def test_run_assessment_blocked_for_out_of_scope_target(monkeypatch):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    result = live_agent.run_assessment("8.8.8.8", "8.8.8.8")

    assert result["_meta"]["status"] == "blocked"


def test_write_report_persists_json_under_reports_dir(tmp_path, monkeypatch):
    """Before this, run_assessment()'s result only ever went to stdout —
    /api/stats, /api/findings, and /api/reports (which all read the most
    recent reports/*.json) never saw anything a live scan found."""
    monkeypatch.chdir(tmp_path)
    result = {"findings": ["x"], "_meta": {"target": "127.0.0.1"}}

    path = live_agent._write_report(result)

    assert path is not None
    assert path.exists()
    assert path.parent.name == "reports"
    import json
    assert json.loads(path.read_text(encoding="utf-8")) == result


def test_blocked_run_does_not_write_a_report(tmp_path, monkeypatch):
    """A scan blocked by guardrails must not leave a fake "completed" report
    on disk for /api/stats to pick up."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)

    live_agent.run_assessment("127.0.0.1", "127.0.0.1")

    assert not (tmp_path / "reports").exists()


def test_sqli_phase_routes_through_the_guardrailed_registry(monkeypatch):
    """The SQLi probe must go through tool_registry.run() (guardrailed), not
    a raw import of the tool function — proven here by the escalation
    guard blocking it without approval, exactly like a direct
    tool_registry.run("webapp.sqli", ...) call would."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.delenv("ESCALATION_APPROVED", raising=False)

    findings = live_agent.phase6_sqli_detection("127.0.0.1", [{"port": 80}])

    # Blocked by EscalationGuard -> no findings extracted, no crash.
    assert findings == []
