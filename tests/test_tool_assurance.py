from nexus.tools.assurance import ToolAssurance, ToolObservation


def test_audit_detects_missing_profile():
    result = ToolAssurance().audit({"demo.tool": lambda: None}, {})
    assert not result[0].healthy
    assert "missing execution profile" in result[0].issues


def test_recommendations_are_bounded_and_require_approval():
    observations = [
        ToolObservation("demo.tool", success=True, duration_seconds=1.0, evidence_count=1)
        for _ in range(5)
    ]
    recommendations = ToolAssurance().recommend(observations)
    assert recommendations
    assert all(item.requires_approval for item in recommendations)


def test_timeout_pattern_generates_review():
    observations = [
        ToolObservation("demo.tool", success=False, duration_seconds=10.0, timed_out=True)
        for _ in range(3)
    ] + [
        ToolObservation("demo.tool", success=True, duration_seconds=1.0)
        for _ in range(2)
    ]
    recommendations = ToolAssurance().recommend(observations)
    assert any(item.kind == "timeout-review" for item in recommendations)


def test_protected_policy_changes_are_never_auto_approved():
    observations = [
        ToolObservation("demo.tool", success=False, duration_seconds=10.0, timed_out=True)
        for _ in range(5)
    ]
    recommendations = ToolAssurance().recommend(observations)
    recommendations += [
        type(recommendations[0])(
            "demo.tool", "policy", "test", 1.0, {"risk": "critical"}
        )
    ]
    safe = ToolAssurance().approved_changes(recommendations)
    assert all("risk" not in item.proposed_change for item in safe)
