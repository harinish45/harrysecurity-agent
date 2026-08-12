"""Tests for audit-required features."""
import pytest
from nexus.tools.registry import tool_registry

def test_new_tool_categories_registered():
    """Verify the 5 new tool categories are registered."""
    all_tools = tool_registry.list_tools()
    domains = set(name.split('.')[0] for name in all_tools.keys())
    
    required_domains = {"container", "api", "physical", "ai_ml", "blockchain"}
    assert required_domains.issubset(domains), f"Missing domains: {required_domains - domains}"

def test_parallel_execution_imports():
    """Verify orchestration engine imports parallel execution utilities."""
    from nexus.orchestration.engine import OrchestrationEngine
    import inspect
    source = inspect.getsource(OrchestrationEngine._execute_phase)
    assert "ThreadPoolExecutor" in source or "gather" in source, "Parallel execution not implemented"

def test_cli_hat_mode_option():
    """Verify --hat-mode option exists in CLI."""
    from nexus.cli import run
    import inspect
    sig = inspect.signature(run)
    assert "hat_mode" in sig.parameters, "--hat-mode option not found in run command"

def test_cli_workflow_option():
    """Verify --workflow option exists in CLI."""
    from nexus.cli import run
    import inspect
    sig = inspect.signature(run)
    assert "workflow" in sig.parameters, "--workflow option not found in run command"
