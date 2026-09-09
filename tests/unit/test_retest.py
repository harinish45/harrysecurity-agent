from nexus.analysis.retest import FindingSnapshot, RetestDiffer


def test_retest_detects_new_resolved_and_changed_findings():
    before = [
        FindingSnapshot("F-1", "high", evidence_hash="a"),
        FindingSnapshot("F-2", "medium", evidence_hash="b"),
        FindingSnapshot("F-3", "low", evidence_hash="c"),
    ]
    after = [
        FindingSnapshot("F-1", "high", evidence_hash="z"),
        FindingSnapshot("F-3", "low", status="resolved", evidence_hash="c"),
        FindingSnapshot("F-4", "critical", evidence_hash="d"),
    ]

    changes = RetestDiffer().compare(before, after)
    assert {item.change for item in changes} == {"changed", "resolved", "new"}
