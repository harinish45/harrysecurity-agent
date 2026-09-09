import pytest

from nexus.agents.capabilities import AgentCapability, CapabilityRegistry, RiskLevel
from nexus.intelligence.llm.provider_registry import (
    ModelClass,
    ProviderProfile,
    ProviderRegistry,
    RoutingPolicy,
)
from nexus.orchestration.planning import PlanTask, PolicyPlanner, TaskState


def test_capability_registry_selects_lowest_risk_eligible_agent():
    registry = CapabilityRegistry(
        [
            AgentCapability("active", "Active", capabilities=("web-recon",), risk_level=RiskLevel.ACTIVE),
            AgentCapability("passive", "Passive", capabilities=("web-recon",), risk_level=RiskLevel.PASSIVE),
        ]
    )
    eligible = registry.eligible(("web-recon",), max_risk=RiskLevel.ACTIVE)
    assert eligible[0].agent_id == "passive"


def test_planner_rejects_unapproved_destructive_task():
    planner = PolicyPlanner(CapabilityRegistry())
    task = PlanTask(
        "t1",
        "destructive test",
        ("impact-validation",),
        risk_level=RiskLevel.DESTRUCTIVE,
        approval_required=False,
    )
    with pytest.raises(ValueError, match="destructive"):
        planner.validate("m1", (task,))


def test_provider_registry_respects_local_and_tool_requirements():
    registry = ProviderRegistry(
        [
            ProviderProfile("cloud", "Cloud", "reasoning", ModelClass.REASONING, local=False),
            ProviderProfile("local", "Local", "qwen", ModelClass.LOCAL, local=True),
        ]
    )
    resolved = registry.resolve(RoutingPolicy("cloud", ("local",), require_local=True))
    assert [item.provider_id for item in resolved] == ["local"]


def test_public_provider_catalogue_contains_no_secret_fields():
    registry = ProviderRegistry([ProviderProfile("local", "Local", "qwen", ModelClass.LOCAL, local=True)])
    payload = registry.public_catalogue()[0]
    assert "api_key" not in payload
    assert "secret" not in payload
    assert payload["provider_id"] == "local"
