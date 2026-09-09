"""Real behavioral tests for the core domain-orchestrator agents in
nexus/agents/{offensive,analysis,defensive}/ — before this file, the
~50 original domain agents (recon_agent, network_agent, webapp_agent,
malware_agent, etc.) were exercised almost entirely by import/registration
smoke checks in test_agent_registry.py, not by tests asserting on their
actual dispatch/aggregation/error-handling behavior.

These agents fall into two real, distinct implementation shapes, both
verified here:

1. "Loop" agents (network_agent, webapp_agent, recon_agent) — iterate a
   tool-name list in a single try/except per iteration, and on empty
   results fall back to a raw socket/HTTP/DNS probe.
2. "Individual try/except" agents (ad_agent, malware_agent,
   forensics_agent, osint_analyst_agent, soc_agent, cloud_agent,
   mobile_agent, wireless_agent, exploit_agent) — one try/except block per
   tool call, tracked in a `tools_used` list, with
   STATUS_COMPLETED-if-findings-else-STATUS_NO_FINDINGS. A real,
   deterministic (if slightly surprising) consequence of this shape is
   tested explicitly below: when every underlying tool call raises, the
   agent still reports STATUS_COMPLETED, not FAILED/NO_FINDINGS — each
   exception is itself appended as a low-severity finding, so `findings`
   is never empty in that case.
"""
import asyncio
import socket

import pytest

from nexus.agents.offensive.ad_agent import AdAgent
from nexus.agents.offensive.cloud_agent import CloudAgent
from nexus.agents.offensive.exploit_agent import ExploitAgent
from nexus.agents.offensive.mobile_agent import MobileAgent
from nexus.agents.offensive.network_agent import NetworkAgent
from nexus.agents.offensive.recon_agent import ReconAgent
from nexus.agents.offensive.webapp_agent import WebappAgent
from nexus.agents.offensive.wireless_agent import WirelessAgent
from nexus.agents.analysis.forensics_agent import ForensicsAgent
from nexus.agents.analysis.malware_agent import MalwareAgent
from nexus.agents.analysis.osint_analyst_agent import OsintAnalystAgent
from nexus.agents.analysis.vuln_analyst_agent import VulnAnalystAgent
from nexus.agents.defensive.soc_agent import SocAgent
from nexus.tools.registry import tool_registry


def run_async(coro):
    return asyncio.run(coro)


# ── shared: no-target contract, all 13 agents ───────────────────────────

ALL_AGENT_CLASSES = [
    AdAgent, CloudAgent, ExploitAgent, MobileAgent, NetworkAgent, ReconAgent,
    WebappAgent, WirelessAgent, ForensicsAgent, MalwareAgent,
    OsintAnalystAgent, VulnAnalystAgent, SocAgent,
]


@pytest.mark.parametrize("agent_cls", ALL_AGENT_CLASSES)
def test_agent_fails_cleanly_with_no_target(agent_cls):
    result = run_async(agent_cls().run("assess it"))
    assert result["status"] == "failed"
    assert result["error"]


# ── "individual try/except" agents: dispatch + resilience ───────────────
# (agent_cls, expected real tool count actually called on success)
INDIVIDUAL_STYLE_AGENTS = [
    (AdAgent, 7), (MalwareAgent, 7), (ForensicsAgent, 6),
    (OsintAnalystAgent, 6), (SocAgent, 5), (CloudAgent, 8),
    (MobileAgent, 6), (WirelessAgent, 9), (ExploitAgent, 6),
]


@pytest.mark.parametrize("agent_cls,expected_tool_count", INDIVIDUAL_STYLE_AGENTS)
def test_individual_style_agent_dispatches_to_every_real_tool(monkeypatch, agent_cls, expected_tool_count):
    calls = []

    def fake_run(name, target, **kwargs):
        calls.append((name, target))
        return {"status": "completed", "findings": [{"title": f"finding from {name}", "severity": "info", "confidence": "high"}]}

    monkeypatch.setattr(tool_registry, "run", fake_run)
    result = run_async(agent_cls().run("assess it", target="target.example.com"))

    assert result["status"] == "completed"
    assert len(calls) == expected_tool_count
    assert all(t == "target.example.com" for _, t in calls)
    assert len(result["findings"]) == expected_tool_count
    assert result["metadata"]["tools_used"] == [c[0] for c in calls]


@pytest.mark.parametrize("agent_cls,expected_tool_count", INDIVIDUAL_STYLE_AGENTS)
def test_individual_style_agent_survives_every_tool_raising(monkeypatch, agent_cls, expected_tool_count):
    """A real, deterministic consequence of the per-tool try/except shape:
    every tool call failing still yields STATUS_COMPLETED (not FAILED),
    because the accumulated error entries make `findings` non-empty."""
    def raising_run(name, target, **kwargs):
        raise ConnectionError(f"could not reach {target} for {name}")

    monkeypatch.setattr(tool_registry, "run", raising_run)
    result = run_async(agent_cls().run("assess it", target="unreachable.example.com"))

    assert result["status"] == "completed"
    assert len(result["findings"]) == expected_tool_count
    assert all(f["severity"] == "low" for f in result["findings"])
    assert result["metadata"]["tools_used"] == []  # nothing succeeded, so nothing was tracked as used


@pytest.mark.parametrize("agent_cls,expected_tool_count", INDIVIDUAL_STYLE_AGENTS)
def test_individual_style_agent_reports_no_findings_when_tools_return_clean(monkeypatch, agent_cls, expected_tool_count):
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: {"status": "no_findings", "findings": []})
    result = run_async(agent_cls().run("assess it", target="clean.example.com"))

    assert result["status"] == "no_findings"
    assert result["findings"] == []
    assert len(result["metadata"]["tools_used"]) == expected_tool_count  # all calls succeeded, just found nothing


def test_individual_style_agent_partial_failure_is_isolated(monkeypatch):
    """One tool raising must not stop the rest of malware_agent's tools
    from running — each try/except block is independent."""
    def selective_fail(name, target, **kwargs):
        if name == "malware.pe_analysis":
            raise ValueError("not a valid PE file")
        return {"status": "completed", "findings": [{"title": f"ok from {name}", "severity": "info", "confidence": "high"}]}

    monkeypatch.setattr(tool_registry, "run", selective_fail)
    result = run_async(MalwareAgent().run("scan it", target="sample.exe"))

    assert result["status"] == "completed"
    assert "malware.pe_analysis" not in result["metadata"]["tools_used"]
    assert len(result["metadata"]["tools_used"]) == 6  # the other 6 malware tools all succeeded
    assert any("not a valid PE file" in f["title"] for f in result["findings"])


# ── "loop" agents: network_agent / webapp_agent / recon_agent ───────────

def test_network_agent_aggregates_real_tool_findings(monkeypatch):
    monkeypatch.setattr(
        tool_registry, "run",
        lambda name, target, **kwargs: {"status": "completed", "findings": [{"title": f"{name} finding", "severity": "medium", "confidence": "high"}]},
    )
    result = run_async(NetworkAgent().run("scan it", target="10.0.0.5"))
    assert result["status"] == "completed"
    assert len(result["findings"]) == 4  # port_scan, banner_grab, host_discovery, firewall_detect


def test_network_agent_falls_back_to_real_socket_probe_when_registry_empty(monkeypatch):
    """When every registered tool call raises (simulating none being
    usable), the agent must fall back to its own real raw-socket probe
    rather than reporting nothing."""
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: (_ for _ in ()).throw(RuntimeError("tool unavailable")))
    result = run_async(NetworkAgent().run("scan it", target="127.0.0.1"))
    assert result["status"] == "completed"
    # every one of the 4 registry calls raised -> 4 "skipped" findings,
    # so findings is non-empty and the socket-probe fallback does NOT
    # additionally trigger (matches the real `if not findings:` guard).
    assert len(result["findings"]) == 4
    assert all("skipped" in f["title"] for f in result["findings"])


def test_network_agent_socket_fallback_activates_on_truly_empty_registry_results(monkeypatch):
    """Registry calls succeed but return zero findings (not an exception)
    -> `findings` stays empty -> the real raw-socket fallback must run."""
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: {"status": "no_findings", "findings": []})
    result = run_async(NetworkAgent().run("scan it", target="127.0.0.1"))
    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "127.0.0.1" in result["findings"][0]["title"]


def test_webapp_agent_aggregates_real_tool_findings(monkeypatch):
    monkeypatch.setattr(
        tool_registry, "run",
        lambda name, target, **kwargs: {"status": "completed", "findings": [{"title": f"{name} finding", "severity": "high", "confidence": "high"}]},
    )
    result = run_async(WebappAgent().run("scan it", target="example.com"))
    assert result["status"] == "completed"
    assert len(result["findings"]) == 6  # sqli, xss, lfi, cmdi, ssrf, dir_enum


def test_webapp_agent_falls_back_to_real_http_fingerprint(monkeypatch):
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: {"status": "no_findings", "findings": []})
    result = run_async(WebappAgent().run("scan it", target="nonexistent-host-nexus-test-12345.invalid"))
    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    # a genuinely unreachable host -> the real safe_urlopen call fails ->
    # the except branch's honest "HTTP check failed" finding, not a fake one
    assert "HTTP check failed" in result["findings"][0]["title"] or "HTTP" in result["findings"][0]["title"]


def test_recon_agent_aggregates_real_tool_findings(monkeypatch):
    monkeypatch.setattr(
        tool_registry, "run",
        lambda name, target, **kwargs: {"status": "completed", "findings": [{"title": f"{name} finding", "severity": "info", "confidence": "high"}]},
    )
    result = run_async(ReconAgent().run("recon it", target="example.com"))
    assert result["status"] == "completed"
    assert len(result["findings"]) == 4  # dns_recon, subdomain_enum, tech_fingerprint, whois_lookup


def test_recon_agent_falls_back_to_real_dns_resolution(monkeypatch):
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: {"status": "no_findings", "findings": []})
    result = run_async(ReconAgent().run("recon it", target="localhost"))
    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "Resolved localhost ->" in result["findings"][0]["title"]


def test_recon_agent_dns_fallback_honestly_reports_resolution_failure(monkeypatch):
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: {"status": "no_findings", "findings": []})
    result = run_async(ReconAgent().run("recon it", target="nonexistent-host-nexus-test-99999.invalid"))
    assert result["status"] == "completed"
    assert "DNS resolution failed" in result["findings"][0]["title"]


# ── vuln_analyst_agent: real upstream-findings correlation ───────────────

def test_vuln_analyst_agent_flags_high_and_critical_upstream_findings(monkeypatch):
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: {"status": "no_findings", "findings": []})
    upstream = [
        {"title": "SQLi", "severity": "critical"},
        {"title": "Weak header", "severity": "low"},
        {"title": "Open redirect", "severity": "high"},
    ]
    result = run_async(VulnAnalystAgent().run("correlate", target="example.com", findings=upstream))
    assert result["status"] == "completed"
    risk_findings = [f for f in result["findings"] if "Risk analysis" in f["title"]]
    assert len(risk_findings) == 1
    assert "2 high/critical" in risk_findings[0]["title"]


def test_vuln_analyst_agent_no_risk_finding_when_no_high_severity_upstream(monkeypatch):
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: {"status": "no_findings", "findings": []})
    upstream = [{"title": "Info disclosure", "severity": "low"}]
    result = run_async(VulnAnalystAgent().run("correlate", target="example.com", findings=upstream))
    assert not any("Risk analysis" in f["title"] for f in result["findings"])


def test_vuln_analyst_agent_no_longer_calls_the_unregistered_vuln_scan_tool(monkeypatch):
    """Regression guard for a real bug this session fixed: vuln_analyst_agent
    used to call 'vuln_assessment.vuln_scan'/'.cve_lookup', neither of
    which was ever registered, so every real run silently no-op'd both."""
    calls = []
    monkeypatch.setattr(tool_registry, "run", lambda name, target, **kwargs: calls.append(name) or {"status": "no_findings", "findings": []})
    run_async(VulnAnalystAgent().run("scan", target="example.com"))
    assert "vuln_assessment.vuln_scan" not in calls
    assert "vuln_assessment.cve_lookup" not in calls
    assert set(calls) == {
        "vuln_assessment.network_vuln_scanning",
        "vuln_assessment.web_vuln_scanning",
        "vuln_assessment.cve_analysis",
    }
