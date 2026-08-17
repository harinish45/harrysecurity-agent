import pytest

from nexus.platform.capabilities import WorkflowMode
from nexus.platform.engagement import EngagementPackage, EngagementRules


def _package() -> EngagementPackage:
    return EngagementPackage(
        engagement_id="eng-001",
        name="Authorized Web Assessment",
        assessment_mode=WorkflowMode.PENTEST,
        objectives=("Assess the approved web application",),
        rules=EngagementRules(
            authorization_reference="ROE-2026-001",
            allowed_targets=("app.example.test",),
            max_concurrency=2,
            max_requests_per_minute=120,
            approval_mode="critical_only",
        ),
        abort_criteria=("Scope deviation",),
        cleanup_plan="Remove temporary assessment artifacts.",
    )


def test_engagement_package_is_valid_and_hash_is_stable():
    package = _package()
    first = package.package_hash()
    second = package.package_hash()
    assert first == second
    assert len(first) == 64


def test_engagement_requires_authorization_and_cleanup():
    package = _package()
    package.rules.validate()

    invalid = EngagementPackage(
        engagement_id="eng-002",
        name="Invalid",
        assessment_mode=WorkflowMode.PENTEST,
        objectives=("test",),
        rules=EngagementRules(
            authorization_reference="ROE-2026-002",
            allowed_targets=("target.test",),
        ),
    )
    with pytest.raises(ValueError, match="cleanup_plan"):
        invalid.validate()
