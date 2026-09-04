"""Covers a real coverage gap: the CLI had zero tests, and `nexus agents
--tier <name>` crashed on every call (filtering a list of (name, class)
tuples with str.endswith())."""
import pytest
from typer.testing import CliRunner

from nexus.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _legal_ack(monkeypatch):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")


def test_agents_lists_all_registered_agents():
    result = runner.invoke(app, ["agents"])
    assert result.exit_code == 0
    assert "recon_agent" in result.output


def test_agents_filters_by_valid_tier():
    result = runner.invoke(app, ["agents", "--tier", "offensive"])
    assert result.exit_code == 0
    assert "recon_agent" in result.output
    assert "malware_agent" not in result.output  # analysis tier, not offensive


def test_agents_rejects_unknown_tier():
    result = runner.invoke(app, ["agents", "--tier", "not-a-real-tier"])
    assert result.exit_code == 1
    assert "Unknown tier" in result.output


def test_agent_run_invokes_the_real_agent():
    result = runner.invoke(app, ["agent", "run", "recon_agent", "--target", "127.0.0.1"])
    assert result.exit_code == 0
    assert "Status:" in result.output
    assert "Findings:" in result.output


def test_agent_run_rejects_unknown_agent_name():
    result = runner.invoke(app, ["agent", "run", "not-a-real-agent", "--target", "127.0.0.1"])
    assert result.exit_code == 1
    assert "Unknown agent" in result.output
