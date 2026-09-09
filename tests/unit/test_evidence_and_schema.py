from nexus.foundation.evidence import Evidence
from nexus.foundation.schema import STATUS_SCHEMA_ERROR, Finding, tool_result


def test_evidence_is_content_addressed_and_verifiable():
    evidence = Evidence.create("m-1", "web.http", "https://example.test", {"status": 200, "body": "ok"})
    assert evidence.verify_integrity()
    assert len(evidence.sha256) == 64


def test_malformed_finding_fails_closed():
    result = tool_result("test.tool", "127.0.0.1", findings=[{"title": "x", "unexpected": True}])
    assert result["status"] == STATUS_SCHEMA_ERROR
    assert result["findings"] == []


def test_finding_requires_title():
    try:
        Finding(title="")
    except ValueError as exc:
        assert "title" in str(exc)
    else:
        raise AssertionError("empty findings must be rejected")
