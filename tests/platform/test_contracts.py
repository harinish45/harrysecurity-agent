from nexus.platform.contracts import (
    CapabilityState,
    Evidence,
    ExecutionPolicy,
    MissionNode,
    Role,
    TenantContext,
    ToolCapability,
    execution_cache_key,
)


def test_execution_policy_requires_authorization_and_scope():
    policy = ExecutionPolicy(authorized=True, allowed_targets=frozenset({"example.test"}))
    assert policy.permits("example.test")
    assert not policy.permits("other.test")
    assert not policy.permits("example.test", requested_destructive=True)


def test_tenant_roles_have_narrow_permissions():
    assert not TenantContext("t", "a", Role.VIEWER, "e").can_execute()
    assert TenantContext("t", "a", Role.OPERATOR, "e").can_execute()
    assert not TenantContext("t", "a", Role.OPERATOR, "e").can_approve()
    assert TenantContext("t", "a", Role.APPROVER, "e").can_approve()
    assert TenantContext("t", "a", Role.ADMIN, "e").can_administer()


def test_capability_progression_is_monotonic():
    capability = ToolCapability("scanner", "1", ("network",))
    promoted = capability.promote(CapabilityState.CALLABLE).promote(CapabilityState.RELIABLE)
    assert promoted.state is CapabilityState.RELIABLE

    try:
        promoted.promote(CapabilityState.CALLABLE)
    except ValueError:
        pass
    else:
        raise AssertionError("capability state must not silently regress")


def test_evidence_hash_is_canonical():
    a = Evidence.from_payload(
        evidence_id="1", mission_id="m", tool="t", target="x", kind="finding",
        payload={"b": 2, "a": 1}, confidence=1.2,
    )
    b = Evidence.from_payload(
        evidence_id="1", mission_id="m", tool="t", target="x", kind="finding",
        payload={"a": 1, "b": 2}, confidence=1.0,
    )
    assert a.payload_hash == b.payload_hash
    assert a.confidence == 1.0


def test_mission_node_dependencies():
    node = MissionNode("n2", "analyze", dependencies=("n1",))
    assert not node.ready(set())
    assert node.ready({"n1"})


def test_execution_cache_key_is_deterministic():
    assert execution_cache_key("t", "1", "x", {"b": 2, "a": 1}) == execution_cache_key(
        "t", "1", "x", {"a": 1, "b": 2}
    )
