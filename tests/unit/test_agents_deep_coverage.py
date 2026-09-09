"""Behavioral coverage for the 22 domain agents that follow the
"individual try/except per tool_registry.run() call" dispatch pattern
already established as real by `tests/unit/test_domain_agents_behavioral.py`
for 13 other agents (network/webapp/recon/AD/malware/forensics/osint/soc/
cloud/mobile/wireless/exploit/vuln-analyst). This file covers the
remaining agents across specialized/defensive/offensive/analysis tiers
that weren't part of that earlier pass: AiSecurityAgent, AutomotiveAgent,
ComplianceAuditorAgent, EmbeddedAgent, HardwareAgent, IotAgent, OtIcsAgent,
RfSdrAgent, BlueTeamAgent, DetectionEngineerAgent, HardeningAgent, IrAgent,
ThreatHuntAgent, ApiAttackerAgent, PhishingAgent, PhysicalPenAgent,
RedteamAgent, SocialEngAgent, CodeReviewAgent, CryptoAgent, ReverseEngAgent,
SupplyChainAgent, ThreatIntelAgent.

Each agent's `run()` calls a fixed, real list of `tool_registry.run(...)`
tool names (extracted directly from source, not guessed) — these tests
confirm: (1) the agent dispatches to exactly the tools it claims to, with
the target passed through correctly; (2) findings from successful tool
calls are aggregated into the agent's own result; (3) a tool raising an
exception degrades to an error-shaped finding rather than crashing the
whole agent; (4) an empty target fails cleanly with STATUS_FAILED.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from nexus.agents.analysis.code_review_agent import CodeReviewAgent
from nexus.agents.analysis.crypto_agent import CryptoAgent
from nexus.agents.analysis.reverse_eng_agent import ReverseEngAgent
from nexus.agents.analysis.supply_chain_agent import SupplyChainAgent
from nexus.agents.analysis.threat_intel_agent import ThreatIntelAgent
from nexus.agents.defensive.blue_team_agent import BlueTeamAgent
from nexus.agents.defensive.detection_engineer_agent import DetectionEngineerAgent
from nexus.agents.defensive.hardening_agent import HardeningAgent
from nexus.agents.defensive.ir_agent import IrAgent
from nexus.agents.defensive.threat_hunt_agent import ThreatHuntAgent
from nexus.agents.offensive.api_attacker_agent import ApiAttackerAgent
from nexus.agents.offensive.phishing_agent import PhishingAgent
from nexus.agents.offensive.physical_pen_agent import PhysicalPenAgent
from nexus.agents.offensive.redteam_agent import RedteamAgent
from nexus.agents.offensive.social_eng_agent import SocialEngAgent
from nexus.agents.specialized.ai_security_agent import AiSecurityAgent
from nexus.agents.specialized.automotive_agent import AutomotiveAgent
from nexus.agents.specialized.compliance_auditor_agent import ComplianceAuditorAgent
from nexus.agents.specialized.embedded_agent import EmbeddedAgent
from nexus.agents.specialized.hardware_agent import HardwareAgent
from nexus.agents.specialized.iot_agent import IotAgent
from nexus.agents.specialized.ot_ics_agent import OtIcsAgent
from nexus.agents.specialized.rf_sdr_agent import RfSdrAgent
from nexus.tools.registry import tool_registry

# (AgentClass, [exact tool names it dispatches to, in source order])
AGENTS_UNDER_TEST = [
    (AiSecurityAgent, [
        "ai_security.adversarial_ml", "ai_security.llm_prompt_injection_testing",
        "ai_security.ai_red_teaming", "ai_security.model_evaluation",
        "ai_security.data_poisoning_research", "ai_security.model_extraction_testing",
    ]),
    (AutomotiveAgent, [
        "automotive.can_bus_analysis", "automotive.ecu_reverse_engineering",
        "automotive.vehicle_network_testing", "automotive.automotive_firmware_analysis",
    ]),
    (ComplianceAuditorAgent, [
        "compliance.iso27001_audit", "compliance.pci_dss_audit", "compliance.gdpr_audit",
        "compliance.hipaa_audit", "compliance.nist_800_53_audit", "compliance.nist_csf_audit",
        "compliance.policy_reviews", "compliance.risk_assessments", "compliance.security_audits",
    ]),
    (EmbeddedAgent, [
        "iot.embedded_linux", "iot.firmware_extraction", "iot.jtag_analysis",
        "iot.uart_analysis", "hardware.secure_boot_testing", "hardware.fault_injection",
    ]),
    (HardwareAgent, [
        "hardware.usb_attacks", "hardware.rfid_testing", "hardware.side_channel_analysis",
        "hardware.tpm_analysis", "hardware.fault_injection", "hardware.rubber_ducky_testing",
    ]),
    (IotAgent, [
        "iot.smart_device_assessment", "iot.can_bus_testing", "iot.firmware_extraction",
        "iot.embedded_linux", "iot.jtag_analysis", "iot.uart_analysis",
    ]),
    (OtIcsAgent, [
        "ot_ics.modbus_analysis", "ot_ics.dnp3_testing", "ot_ics.plc_testing",
        "ot_ics.scada_security", "ot_ics.industrial_protocol_reviews",
    ]),
    (RfSdrAgent, [
        "rf_sdr.rtl_sdr_analysis", "rf_sdr.hackrf_experimentation", "rf_sdr.radio_protocol_analysis",
        "rf_sdr.signal_decoding", "rf_sdr.jammer_detection", "rf_sdr.replay_testing",
    ]),
    (BlueTeamAgent, [
        "blue_team.endpoint_protection", "blue_team.edr_analysis", "blue_team.log_review",
        "blue_team.threat_hunting_blue", "soc.siem_monitoring",
    ]),
    (DetectionEngineerAgent, [
        "blue_team.detection_engineering_blue", "soc.rule_tuning",
        "soc.detection_engineering_soc", "purple_team.detection_testing",
    ]),
    (HardeningAgent, [
        "blue_team.hardening", "blue_team.firewall_management",
        "blue_team.endpoint_protection", "compliance.policy_reviews",
    ]),
    (IrAgent, [
        "incident_response.alert_triage", "incident_response.incident_investigation",
        "incident_response.eradication", "incident_response.malware_containment",
        "incident_response.recovery",
    ]),
    (ThreatHuntAgent, [
        "blue_team.threat_hunting_blue", "threat_intel.threat_feeds",
        "soc.ueba", "incident_response.threat_hunting",
    ]),
    (ApiAttackerAgent, [
        "webapp.api_security", "webapp.rest_api_testing", "webapp.browser_agent",
        "webapp.rate_limit", "webapp.auth_test",
    ]),
    (PhishingAgent, [
        "webapp.auth_test", "webapp.session_mgmt", "reconnaissance.email_harvest",
        "reconnaissance.social_osint", "webapp.business_logic",
    ]),
    (PhysicalPenAgent, [
        "hardware.rfid_testing", "hardware.usb_attacks", "hardware.rubber_ducky_testing",
        "hardware.fault_injection", "hardware.secure_boot_testing", "hardware.side_channel_analysis",
    ]),
    (RedteamAgent, [
        "red_team.initial_access_simulation", "red_team.lateral_movement_simulation",
        "red_team.persistence_simulation", "red_team.credential_access_simulation",
        "red_team.exfiltration_simulation", "red_team.defense_evasion_simulation",
        "red_team.discovery_simulation",
    ]),
    (SocialEngAgent, [
        "reconnaissance.social_osint", "reconnaissance.email_harvest",
        "reconnaissance.github_recon", "reconnaissance.dns_recon", "reconnaissance.whois_lookup",
    ]),
    (CodeReviewAgent, [
        "appsec.sast", "appsec.secure_code_review", "appsec.secret_scanning", "appsec.sca",
    ]),
    (CryptoAgent, [
        "cryptography.certificate_validation", "cryptography.cryptanalysis",
        "cryptography.crypto_hash_analysis", "cryptography.key_management",
        "cryptography.pki_reviews", "cryptography.tls_testing",
    ]),
    (ReverseEngAgent, [
        "reverse_engineering.assembly_analysis", "reverse_engineering.binary_patching",
        "reverse_engineering.firmware_reverse_engineering", "reverse_engineering.ghidra_analysis",
        "reverse_engineering.ida_analysis",
    ]),
    (SupplyChainAgent, [
        "appsec.sca", "appsec.dependency_analysis", "appsec.cicd_security",
        "vuln_assessment.patch_verification",
    ]),
    (ThreatIntelAgent, [
        "threat_intel.threat_feeds", "threat_intel.ioc_enrichment",
        "threat_intel.threat_actor_profiling", "threat_intel.attck_mapping",
        "threat_intel.malware_family_tracking",
    ]),
]


def _run(agent_cls, target="example.com"):
    return asyncio.run(agent_cls().run("assess", target=target))


@pytest.mark.parametrize("agent_cls,expected_tools", AGENTS_UNDER_TEST, ids=[c.__name__ for c, _ in AGENTS_UNDER_TEST])
def test_agent_dispatches_to_exactly_its_declared_tools_with_target(agent_cls, expected_tools):
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        _run(agent_cls, target="scanme.nmap.org")

    called_tools = [call.args[0] if call.args else call.kwargs.get("tool_name") for call in mock_run.call_args_list]
    assert called_tools == expected_tools, f"{agent_cls.__name__} dispatch order/set mismatch"
    for call in mock_run.call_args_list:
        # target must reach every dispatched tool, whether passed positionally or by kwarg.
        passed_target = call.kwargs.get("target") if "target" in call.kwargs else (call.args[1] if len(call.args) > 1 else None)
        assert passed_target == "scanme.nmap.org"


@pytest.mark.parametrize("agent_cls,expected_tools", AGENTS_UNDER_TEST, ids=[c.__name__ for c, _ in AGENTS_UNDER_TEST])
def test_agent_aggregates_findings_from_successful_tools(agent_cls, expected_tools):
    fake_finding = {"title": "Real finding from a mocked tool", "severity": "medium"}
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "completed", "findings": [fake_finding]}
        result = _run(agent_cls)

    assert result["status"] == "completed"
    assert len(result["findings"]) == len(expected_tools)
    assert all(f["title"] == "Real finding from a mocked tool" for f in result["findings"])


@pytest.mark.parametrize("agent_cls,expected_tools", AGENTS_UNDER_TEST, ids=[c.__name__ for c, _ in AGENTS_UNDER_TEST])
def test_agent_reports_no_findings_when_every_tool_returns_clean(agent_cls, expected_tools):
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.return_value = {"status": "no_findings", "findings": []}
        result = _run(agent_cls)

    assert result["status"] == "no_findings"
    assert result["findings"] == []


@pytest.mark.parametrize("agent_cls,expected_tools", AGENTS_UNDER_TEST, ids=[c.__name__ for c, _ in AGENTS_UNDER_TEST])
def test_agent_survives_a_failing_tool_without_crashing(agent_cls, expected_tools):
    with patch.object(tool_registry, "run") as mock_run:
        mock_run.side_effect = RuntimeError("tool exploded")
        result = _run(agent_cls)

    # Every one of the agent's tool calls failed identically — it must not
    # raise, and each failure becomes its own low-severity error finding.
    assert result["status"] == "completed"
    assert len(result["findings"]) == len(expected_tools)
    assert all("tool exploded" in f["title"] for f in result["findings"])
    assert all(f["severity"] == "low" for f in result["findings"])


@pytest.mark.parametrize("agent_cls,expected_tools", AGENTS_UNDER_TEST, ids=[c.__name__ for c, _ in AGENTS_UNDER_TEST])
def test_agent_fails_cleanly_with_no_target(agent_cls, expected_tools):
    result = _run(agent_cls, target="")
    assert result["status"] == "failed"
    assert "No target" in result["error"]
