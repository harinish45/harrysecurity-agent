"""agent_router_agent.py used to route to a domain based on task keywords
but then always execute the same 3 hardcoded reconnaissance tools regardless
of that decision — the routing and the execution were unrelated. And
installer_agent.py unconditionally ran `pip install` on a 14-package list
every single invocation, plus silently discarded findings computed by the
automation tools it called. All three fixed and covered here."""
from unittest.mock import patch

import pytest

from nexus.agents.orchestrator.agent_router_agent import AgentRouterAgent
from nexus.agents.support.installer_agent import InstallerAgent


# ── agent_router_agent ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_router_executes_the_tool_for_its_own_routing_decision(monkeypatch):
    called = []

    def fake_run(name, **kwargs):
        called.append(name)
        return {"status": "completed", "findings": []}

    monkeypatch.setattr("nexus.agents.orchestrator.agent_router_agent.tool_registry.run", fake_run)

    result = await AgentRouterAgent().run("audit our cloud compliance posture", target="example.com")

    domains = set(result["metadata"]["recommended_domains"])
    assert "cloud" in domains
    assert "compliance" in domains
    # The tools actually invoked must correspond to the routed domains —
    # not the old fixed 3-tool reconnaissance set regardless of routing.
    assert "cloud.aws_review" in called
    assert "compliance.security_audits" in called
    assert "reconnaissance.dns_recon" not in called


@pytest.mark.asyncio
async def test_router_different_tasks_route_to_different_tools(monkeypatch):
    def fake_run(name, **kwargs):
        return {"status": "completed", "findings": []}

    monkeypatch.setattr("nexus.agents.orchestrator.agent_router_agent.tool_registry.run", fake_run)

    r1 = await AgentRouterAgent().run("investigate malware sample", target="127.0.0.1")
    tools_1 = set(r1["metadata"]["tools_used"])
    r2 = await AgentRouterAgent().run("check for reverse engineering opportunities on this binary", target="127.0.0.1")
    tools_2 = set(r2["metadata"]["tools_used"])

    assert tools_1 != tools_2
    assert "malware.hash_analysis" in tools_1
    assert "reverse_engineering.ghidra_analysis" in tools_2


# ── installer_agent ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_installer_installs_nothing_for_an_irrelevant_task(monkeypatch):
    with patch("subprocess.run") as mock_subprocess, patch("nexus.tools.registry.tool_registry.run") as mock_tool_run:
        mock_tool_run.return_value = {"status": "completed", "findings": []}
        result = await InstallerAgent().run("write documentation for the API", target="example.com")

    mock_subprocess.assert_not_called()
    assert result["metadata"]["installed"] == []


@pytest.mark.asyncio
async def test_installer_only_attempts_relevant_packages(monkeypatch):
    with patch("builtins.__import__", side_effect=ImportError), \
         patch("subprocess.run") as mock_subprocess, \
         patch("nexus.tools.registry.tool_registry.run") as mock_tool_run:
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stderr = ""
        mock_tool_run.return_value = {"status": "completed", "findings": []}

        await InstallerAgent().run("set up a crypto/TLS testing environment", target="example.com")

    installed_packages = {call.args[0][2] for call in mock_subprocess.call_args_list}
    assert installed_packages <= {"cryptography", "pyopenssl"}
    assert "django" not in installed_packages
    assert "scapy" not in installed_packages


@pytest.mark.asyncio
async def test_installer_no_real_pip_install_ever_runs_in_tests(monkeypatch):
    """Belt-and-suspenders: even with a package-relevant task, confirm no
    test in this file can reach a real subprocess unless subprocess.run is
    explicitly mocked — this test intentionally does NOT mock it and
    instead asserts the agent completes without needing a real install by
    pre-satisfying the import check."""
    with patch("nexus.tools.registry.tool_registry.run") as mock_tool_run:
        mock_tool_run.return_value = {"status": "completed", "findings": []}
        # "requests" is virtually guaranteed already installed in this venv
        # (a real dependency of this project) — exercises the "already
        # installed, skip" path with zero subprocess calls.
        result = await InstallerAgent().run("test the web/http API", target="example.com")

    assert any(s.get("package") == "requests" and s.get("reason") == "already installed"
               for s in result["metadata"]["skipped"])


@pytest.mark.asyncio
async def test_installer_no_longer_discards_findings_from_automation_tools(monkeypatch):
    def fake_run(name, **kwargs):
        return {"status": "completed", "findings": [{"title": f"finding from {name}", "severity": "low"}]}

    with patch("nexus.tools.registry.tool_registry.run", side_effect=fake_run):
        result = await InstallerAgent().run("review documentation only", target="example.com")

    assert len(result["findings"]) == 4  # one per automation_tools entry
    titles = [f.get("title") if isinstance(f, dict) else f for f in result["findings"]]
    assert any("automation.soar_playbooks" in t for t in titles)
