from nexus.orchestration.decision.attack_chain import AttackChain
from nexus.orchestration.decision.param_optimizer import ParamOptimizer
from nexus.orchestration.decision.strategy_engine import StrategyEngine
from nexus.orchestration.decision.tool_selector import ToolSelector
from nexus.tools.registry import tool_registry


def test_strategy_engine_picks_sequential_for_a_linear_chain():
    assert StrategyEngine.choose([["A"], ["B"], ["C"]]) == "sequential"


def test_strategy_engine_picks_parallel_for_one_wide_batch():
    assert StrategyEngine.choose([["A", "B", "C"]]) == "parallel"


def test_strategy_engine_picks_mixed_for_a_diamond():
    assert StrategyEngine.choose([["A"], ["B", "C"], ["D"]]) == "mixed"


def test_strategy_engine_handles_no_batches():
    assert StrategyEngine.choose([]) == "sequential"


def test_param_optimizer_shortens_timeout_for_private_targets():
    private_timeout = ParamOptimizer.timeout_for("127.0.0.1", base_timeout=300)
    public_timeout = ParamOptimizer.timeout_for("example.com", base_timeout=300)
    assert private_timeout < public_timeout
    assert public_timeout == 300


def test_tool_selector_returns_empty_for_unknown_domain():
    assert ToolSelector.select("this-domain-does-not-exist", limit=3) == []


def test_tool_selector_respects_limit_and_stays_within_domain():
    domain = tool_registry.get_domains()[0]
    selected = ToolSelector.select(domain, limit=2)
    assert len(selected) <= 2
    assert all(name.startswith(f"{domain}.") for name in selected)


def test_attack_chain_recommends_next_domains_from_findings():
    findings = [
        {"title": "Open port", "tool": "reconnaissance.subdomain_enum", "severity": "medium"},
        {"title": "Outdated CMS", "tool": "reconnaissance.tech_fingerprint", "severity": "high"},
    ]
    recommendations = AttackChain.recommend_next(findings, limit=3)
    assert recommendations  # non-empty
    assert "network" in recommendations or "webapp" in recommendations


def test_attack_chain_defaults_to_reconnaissance_with_no_findings():
    assert AttackChain.recommend_next([]) == ["reconnaissance"]
