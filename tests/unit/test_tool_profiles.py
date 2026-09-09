from nexus.agents.capabilities import RiskLevel
from nexus.tools.profile import ResourceClass, ToolProfile, profile_from_metadata


def test_tool_profile_validates_and_serializes_operational_constraints():
    profile = ToolProfile(
        name="network.port_scan",
        domain="network",
        capabilities=("port_discovery",),
        risk_level=RiskLevel.LOW,
        resource_class=ResourceClass.NETWORK,
        timeout_seconds=120,
        max_concurrency=8,
        rate_limit_per_minute=60,
        supports_parallel=True,
        supports_resume=True,
    )
    payload = profile.to_dict()

    assert payload["timeout_seconds"] == 120
    assert payload["max_concurrency"] == 8
    assert payload["supports_parallel"] is True
    assert payload["capabilities"] == ["port_discovery"]


def test_legacy_metadata_gets_safe_default_profile():
    profile = profile_from_metadata("reconnaissance.dns_recon", {"domain": "reconnaissance"})

    assert profile.name == "reconnaissance.dns_recon"
    assert profile.domain == "reconnaissance"
    assert profile.timeout_seconds == 300


def test_hardware_profile_requires_hardware_resource_class():
    profile = ToolProfile(
        name="hardware.usb_testing",
        domain="hardware",
        requires_hardware=True,
        resource_class=ResourceClass.HARDWARE,
    )
    profile.validate()
