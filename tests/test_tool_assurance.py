import dataclasses

import pytest

from nexus.agents.capabilities import RiskLevel
from nexus.tools.assurance import ToolAssurance, ToolObservation
from nexus.tools.profile import ToolProfile
from nexus.tools.registry import ToolRegistry


def test_audit_detects_missing_profile():
    result = ToolAssurance().audit({"demo.tool": lambda: None}, {})
    assert not result[0].healthy
    assert "missing execution profile" in result[0].issues


def test_audit_detects_a_tool_that_always_raises():
    """A registered tool that is `callable()` but raises on every real
    invocation must not be reported healthy just because it exists and has
    a well-formed profile — this is the exact false-assurance signal the
    audit exists to catch (regression for the audit that never actually
    called the tool it was checking)."""

    def always_fails(**kwargs):
        raise RuntimeError("always fails")

    profile = ToolProfile(name="recon.fake_scan", domain="recon", risk_level=RiskLevel.LOW)
    result = ToolAssurance().audit(
        {"recon.fake_scan": always_fails}, {"recon.fake_scan": profile}
    )

    check = result[0]
    assert not check.callable_ok
    assert not check.healthy
    assert any("always fails" in issue for issue in check.issues)


def test_assurance_report_flags_a_broken_registered_tool_as_unhealthy():
    """End-to-end version of the same scenario through the real
    ToolRegistry.assurance_report() path an operator dashboard or CI gate
    would actually call."""
    registry = ToolRegistry()
    registry.register(
        "recon.fake_scan",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("always fails")),
        metadata={"domain": "recon", "risk_level": "low"},
    )

    report = registry.assurance_report()

    assert report["total"] == 1
    assert report["unhealthy"] == 1
    assert report["healthy"] == 0
    check = report["checks"][0]
    assert not check.callable_ok
    assert not check.healthy


def test_recommendations_require_approval():
    observations = [ToolObservation("demo.tool", True, 1.0, evidence_count=1) for _ in range(5)]
    recommendations = ToolAssurance().recommend(observations)
    assert recommendations
    assert all(item.requires_approval for item in recommendations)


def test_timeout_pattern_generates_review():
    observations = [ToolObservation("demo.tool", False, 10.0, timed_out=True) for _ in range(3)]
    observations += [ToolObservation("demo.tool", True, 1.0) for _ in range(2)]
    recommendations = ToolAssurance().recommend(observations)
    assert any(item.kind == "timeout-review" for item in recommendations)


def test_protected_policy_changes_are_never_auto_approved():
    observations = [ToolObservation("demo.tool", False, 10.0, timed_out=True) for _ in range(5)]
    recommendations = list(ToolAssurance().recommend(observations))
    recommendations.append(
        type(recommendations[0])("demo.tool", "policy", "test", 1.0, {"risk": "critical"})
    )
    safe = ToolAssurance().approved_changes(recommendations)
    assert all("risk" not in item.proposed_change for item in safe)


def test_protected_fields_boundary_is_immutable():
    """ToolAssurance must be frozen so its protected_fields safety boundary
    cannot be overwritten by a caller holding the instance (e.g. to disable
    the risk/credentials/scope/authorization/allowed_targets guard)."""
    assurance = ToolAssurance()
    with pytest.raises(dataclasses.FrozenInstanceError):
        assurance.protected_fields = frozenset()
