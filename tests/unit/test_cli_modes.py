"""CLI-level coverage for the mode-separation commands added on top of
`nexus run` (nexus pentest/bounty/ctf/redteam/blueteam/compliance assess,
nexus benchmark) — each should share `run()`'s guardrails/engine path and
exit cleanly with a mocked LLM/tool layer (no real network calls)."""
import json
import os
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from nexus.cli import app

runner = CliRunner()
os.environ.setdefault("NEXUS_LEGAL_ACK", "1")


@pytest.fixture(autouse=True)
def _legal_ack(monkeypatch, tmp_path):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.setenv("NEXUS_CHECKPOINT_DIR", str(tmp_path / "checkpoints"))


@pytest.fixture
def mocked_mission(tmp_path):
    """Same mocking strategy as tests/integration/test_full_mission.py:
    canned LLM plan, no real tool execution, report writes redirected under
    tmp_path so the test stays hermetic."""
    with patch("nexus.intelligence.llm.router.LLMRouter.complete") as mock_complete:
        mock_complete.return_value = json.dumps([
            {"agent": "recon_agent", "task": "Reconnaissance", "domain": "reconnaissance"}
        ])
        with patch("nexus.tools.executor.ToolExecutor.run") as mock_tool_run:
            mock_tool_run.return_value = {
                "tool": "reconnaissance.subdomain_enum", "target": "127.0.0.1",
                "status": "no_findings", "findings": [], "summary": "No findings",
                "error": "", "metadata": {},
            }
            with patch("nexus.reporting.generator.ReportGenerator.write") as mock_write:
                mock_write.return_value = tmp_path / "reports" / "test.md"
                yield mock_complete


@pytest.mark.parametrize("command,args", [
    ("pentest", ["--target", "127.0.0.1", "--mission", "test-pentest"]),
    ("bounty", ["--target", "127.0.0.1", "--mission", "test-bounty"]),
    ("ctf", ["--target", "127.0.0.1", "--category", "web", "--mission", "test-ctf"]),
    ("redteam", ["--target", "127.0.0.1", "--mission", "test-redteam"]),
    ("blueteam", ["--target", "127.0.0.1", "--mission", "test-blueteam"]),
])
def test_mode_command_completes_a_mission(mocked_mission, command, args):
    result = runner.invoke(app, [command, *args])
    assert result.exit_code == 0, result.output
    assert "Mission" in result.output
    assert "completed" in result.output


def test_compliance_assess_completes_a_mission(mocked_mission):
    result = runner.invoke(app, ["compliance", "assess", "--target", "127.0.0.1",
                                  "--framework", "SOC2", "--mission", "test-compliance"])
    assert result.exit_code == 0, result.output
    assert "completed" in result.output


def test_benchmark_runs_the_bundled_smoke_suite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("nexus.intelligence.llm.router.LLMRouter.complete") as mock_complete:
        mock_complete.return_value = "CWE-1004"
        result = runner.invoke(app, ["benchmark", "--suite", "intercode_ctf"])
    assert result.exit_code == 0, result.output
    assert "InterCode-CTF" in result.output
    assert (tmp_path / "benchmarks" / "history.jsonl").exists()


def test_benchmark_rejects_unknown_suite():
    result = runner.invoke(app, ["benchmark", "--suite", "not-a-real-suite"])
    assert result.exit_code == 1
    assert "Unknown suite" in result.output
