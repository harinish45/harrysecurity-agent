#!/usr/bin/env python3
"""
Unit tests for the upgraded Automotive Security Laboratory tools in NEXUS-STRIKE.
Covers:
- automotive.can_bus_analysis
- automotive.ecu_reverse_engineering
- automotive.automotive_firmware_analysis
- automotive.vehicle_network_testing
- automotive.v2x_security
- AutomotiveAgent specialized agent
"""
import pytest
from nexus.foundation.config import config
from nexus.tools.registry import tool_registry
from nexus.agents.specialized.automotive_agent import AutomotiveAgent
from nexus.tools.automotive import (
    can_bus_analysis,
    ecu_reverse_engineering,
    automotive_firmware_analysis,
    vehicle_network_testing,
    v2x_security,
)


@pytest.fixture(autouse=True)
def setup_guardrails(monkeypatch):
    """Ensure tests satisfy Nexus guardrails (Legal, Escalation, and Scope allow-list)."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.setenv("ESCALATION_APPROVED", "true")
    monkeypatch.setattr(config, "nexus_allowed_targets", "*")


def test_can_bus_analysis_basic():
    """Verify can_bus_analysis runs cleanly on standard target."""
    result = tool_registry.run("automotive.can_bus_analysis", target="vcan0")
    assert isinstance(result, dict)
    assert result["tool"] == "automotive.can_bus_analysis"
    assert result["status"] == "completed"
    assert isinstance(result["findings"], list)
    assert "summary" in result


def test_can_bus_analysis_attack_detection():
    """Verify can_bus_analysis detects ID 0x000 Bus-Off DoS and Mode 04 Clear DTC."""
    attack_log = (
        "(1600000000.001) can0 000#0000000000000000\n"
        "(1600000000.002) can0 7DF#0204000000000000\n"
        "(1600000000.003) can0 7DF#0209020000000000\n"
    )
    result = tool_registry.run(
        "automotive.can_bus_analysis",
        target="can0",
        log_content=attack_log,
    )
    findings = result["findings"]
    titles = [f["title"] for f in findings]
    
    # Assert ID 0x000 Bus-Off critical finding
    assert any("Bus-Off" in t or "Denial-of-Service" in t for t in titles)
    # Assert Clear DTC finding
    assert any("Clear DTC" in t for t in titles)
    # Assert VIN query finding
    assert any("VIN" in t for t in titles)


def test_ecu_reverse_engineering_basic():
    """Verify ecu_reverse_engineering runs and detects UDS services."""
    result = tool_registry.run("automotive.ecu_reverse_engineering", target="ecu-test.local")
    assert isinstance(result, dict)
    assert result["tool"] == "automotive.ecu_reverse_engineering"
    assert result["status"] == "completed"
    assert len(result["findings"]) > 0


def test_ecu_reverse_engineering_weak_seeds():
    """Verify detection of zero-seeds and static seeds."""
    # Test zero-seed (backdoor unlock)
    zero_seed_res = tool_registry.run(
        "automotive.ecu_reverse_engineering",
        target="ecu-test.local",
        seed_samples=[[0x00, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00]],
    )
    titles = [f["title"] for f in zero_seed_res["findings"]]
    assert any("Zero-Seed" in t for t in titles)

    # Test static seed (replay)
    static_seed_res = tool_registry.run(
        "automotive.ecu_reverse_engineering",
        target="ecu-test.local",
        seed_samples=[[0xDE, 0xAD, 0xBE, 0xEF], [0xDE, 0xAD, 0xBE, 0xEF]],
    )
    static_titles = [f["title"] for f in static_seed_res["findings"]]
    assert any("Static Seed" in t for t in static_titles)


def test_automotive_firmware_analysis_basic():
    """Verify firmware analysis detects architecture and sensitive strings."""
    result = tool_registry.run("automotive.automotive_firmware_analysis", target="ecu-firmware.bin")
    assert isinstance(result, dict)
    assert result["tool"] == "automotive.automotive_firmware_analysis"
    assert result["status"] == "completed"
    assert len(result["findings"]) > 0

    titles = [f["title"] for f in result["findings"]]
    # Should detect TriCore from synthetic image
    assert any("TriCore" in t for t in titles)
    # Should detect unencrypted firmware or sensitive artifacts
    assert any("Sensitive Automotive Artifact" in t or "Firmware" in t for t in titles)


def test_automotive_firmware_srec_parsing():
    """Verify Motorola S-Record parser parses S3 records and validates checksum."""
    srec_sample = (
        "S00F000068656C6C6F202020202000003C\n"
        "S307800000005AA519\n"
        "S705800000007A\n"
    )
    result = tool_registry.run(
        "automotive.automotive_firmware_analysis",
        target="flash.s19",
        firmware_text=srec_sample,
    )
    assert result["metadata"]["format"] == "Motorola S-Record (SREC)"
    assert result["status"] == "completed"


def test_vehicle_network_testing_basic():
    """Verify vehicle network testing tool audits DoIP and SOME/IP."""
    result = tool_registry.run(
        "automotive.vehicle_network_testing",
        target="127.0.0.1",
    )
    assert isinstance(result, dict)
    assert result["tool"] == "automotive.vehicle_network_testing"
    assert result["status"] == "completed"
    assert len(result["findings"]) > 0

    titles = [f["title"] for f in result["findings"]]
    assert any("IVN Gateway Domain Isolation" in t for t in titles)
    assert any("SecOC" in t for t in titles)


def test_v2x_security_basic():
    """Verify v2x_security tool executes cleanly."""
    result = tool_registry.run("automotive.v2x_security", target="127.0.0.1")
    assert isinstance(result, dict)
    assert result["tool"] == "automotive.v2x_security"
    assert result["status"] == "completed"


@pytest.mark.asyncio
async def test_automotive_agent_execution():
    """Verify AutomotiveAgent orchestrates all automotive tools seamlessly."""
    agent = AutomotiveAgent()
    result = await agent.run(task="Perform full automotive cyber assessment", target="127.0.0.1")
    assert isinstance(result, dict)
    assert result["tool"] == "automotive_agent"
    assert result["status"] == "completed"
    assert len(result["findings"]) > 0
    assert len(result["metadata"]["tools_used"]) == 4
