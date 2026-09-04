"""Behavioral tests for a further sample of agents across tiers that
previously had zero test coverage beyond the structural "has a run method"
check in test_agent_registry.py — defensive (soc_agent), analysis
(malware_agent), specialized (iot_agent), support (searcher_agent)."""
import pytest

from nexus.agents.analysis.malware_agent import MalwareAgent
from nexus.agents.defensive.soc_agent import SocAgent
from nexus.agents.specialized.iot_agent import IotAgent
from nexus.agents.support.searcher_agent import SearcherAgent


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_cls", [SocAgent, MalwareAgent, IotAgent, SearcherAgent])
async def test_fails_cleanly_with_no_target(agent_cls):
    result = await agent_cls().run("some task", target="")
    assert result["status"] == "failed"
    assert result["error"]


@pytest.mark.asyncio
async def test_soc_agent_aggregates_findings_from_all_soc_tools(monkeypatch):
    def fake_run(name, **kwargs):
        return {"status": "completed", "findings": [{"title": f"finding from {name}", "severity": "low"}]}

    monkeypatch.setattr("nexus.agents.defensive.soc_agent.tool_registry.run", fake_run)

    result = await SocAgent().run("investigate alerts", target="127.0.0.1")

    assert result["status"] == "completed"
    assert len(result["findings"]) == 5  # one per SOC tool
    assert set(result["metadata"]["tools_used"]) == {
        "soc.alert_investigation", "soc.log_correlation", "soc.siem_monitoring",
        "soc.soar_automation", "soc.dashboard_creation",
    }


@pytest.mark.asyncio
async def test_soc_agent_survives_a_tool_failure_and_reports_it(monkeypatch):
    def flaky_run(name, **kwargs):
        if name == "soc.log_correlation":
            raise RuntimeError("simulated tool crash")
        return {"status": "completed", "findings": []}

    monkeypatch.setattr("nexus.agents.defensive.soc_agent.tool_registry.run", flaky_run)

    result = await SocAgent().run("investigate", target="127.0.0.1")

    assert result["status"] in ("completed", "no_findings")
    assert any("Log correlation error" in f.get("title", "") for f in result["findings"])
    # The other 4 tools still ran despite one failing.
    assert "soc.siem_monitoring" in result["metadata"]["tools_used"]


@pytest.mark.asyncio
async def test_malware_agent_runs_all_seven_malware_tools(monkeypatch):
    calls = []

    def fake_run(name, **kwargs):
        calls.append(name)
        return {"status": "completed", "findings": []}

    monkeypatch.setattr("nexus.agents.analysis.malware_agent.tool_registry.run", fake_run)

    result = await MalwareAgent().run("analyze sample", target="127.0.0.1")

    assert len(calls) == 7
    assert all(name.startswith("malware.") for name in calls)
    assert result["status"] == "no_findings"  # no tool returned findings


@pytest.mark.asyncio
async def test_iot_agent_covers_hardware_and_firmware_domains(monkeypatch):
    calls = []

    def fake_run(name, **kwargs):
        calls.append(name)
        return {"status": "completed", "findings": [{"title": "insecure default credentials", "severity": "high"}]}

    monkeypatch.setattr("nexus.agents.specialized.iot_agent.tool_registry.run", fake_run)

    result = await IotAgent().run("assess device", target="192.168.1.50")

    assert "iot.firmware_extraction" in calls
    assert "iot.jtag_analysis" in calls
    assert result["status"] == "completed"
    assert len(result["findings"]) == len(calls)


@pytest.mark.asyncio
async def test_searcher_agent_deduplicates_identical_findings(monkeypatch):
    def fake_run(name, **kwargs):
        # Every source reports the exact same finding title — a real
        # scenario (subdomain enum and DNS recon both surfacing the same host).
        return {"status": "completed", "findings": [{"title": "duplicate.example.com found", "severity": "info"}]}

    monkeypatch.setattr("nexus.agents.support.searcher_agent.tool_registry.run", fake_run)

    result = await SearcherAgent().run("gather intel", target="example.com")

    assert result["metadata"]["total_raw_findings"] == 5  # 5 sources, all duplicates
    assert result["metadata"]["total_unique_findings"] == 1
    assert len(result["findings"]) == 1
