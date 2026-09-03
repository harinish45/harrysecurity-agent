import pytest

from nexus.compliance.frameworks import (
    ALL_MAPPINGS,
    FRAMEWORKS,
    NEXUS_CAPABILITIES,
    Control,
    ControlMapping,
    get_mapping,
    get_mappings,
    unmapped_controls,
)


def test_catalog_loads_and_is_nonempty():
    assert len(ALL_MAPPINGS) > 0
    assert all(isinstance(m, ControlMapping) for m in ALL_MAPPINGS)


def test_every_framework_has_entries():
    for framework in FRAMEWORKS:
        mappings = get_mappings(framework)
        assert len(mappings) >= 10, f"{framework} has too few controls: {len(mappings)}"
        assert all(m.control.framework == framework for m in mappings)


def test_total_control_count_is_modest():
    # 6 frameworks x ~10-16 controls each: a modest illustrative catalog,
    # not an exhaustive reproduction of any framework.
    assert 60 <= len(ALL_MAPPINGS) <= 120


def test_no_duplicate_control_ids():
    ids = [m.control.id for m in ALL_MAPPINGS]
    assert len(ids) == len(set(ids)), "duplicate control IDs found in catalog"


def test_get_mapping_returns_none_for_unknown_id():
    assert get_mapping("NOT-A-REAL-CONTROL") is None


def test_get_mapping_returns_the_right_control():
    mapping = get_mapping("SOC2-CC6.1")
    assert mapping is not None
    assert mapping.control.id == "SOC2-CC6.1"
    assert mapping.control.framework == "SOC2"


def test_get_mappings_rejects_unknown_framework():
    with pytest.raises(ValueError):
        get_mappings("NOT_A_FRAMEWORK")


def test_mapped_capabilities_are_all_real():
    for mapping in ALL_MAPPINGS:
        if mapping.nexus_capability is not None:
            assert mapping.nexus_capability in NEXUS_CAPABILITIES


def test_every_capability_is_used_at_least_once():
    used = {m.nexus_capability for m in ALL_MAPPINGS if m.nexus_capability is not None}
    missing = NEXUS_CAPABILITIES - used
    assert not missing, f"declared capabilities never mapped to any control: {missing}"


def test_unmapped_controls_are_honestly_gaps():
    unmapped = unmapped_controls()
    assert len(unmapped) > 0, "expected at least some controls to have no NEXUS mapping"
    assert all(isinstance(control, Control) for control in unmapped)
    mapped_ids = {m.control.id for m in ALL_MAPPINGS if m.nexus_capability is not None}
    for control in unmapped:
        assert control.id not in mapped_ids


def test_control_and_mapping_reject_invalid_input():
    with pytest.raises(ValueError):
        Control(id="X-1", framework="NOT_A_FRAMEWORK", title="t", description="d")

    bogus_control = Control(id="X-2", framework="SOC2", title="t", description="d")
    with pytest.raises(ValueError):
        ControlMapping(control=bogus_control, nexus_capability="not_a_real_capability", evidence_note="n")
