from nexus.advanced.patch_validation import PatchValidator


class _StubExecutor:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, tool_name, target, **kwargs):
        self.calls.append((tool_name, target))
        return self.result


def test_verify_fix_still_present_when_matching_finding_recurs():
    finding = {
        "id": "F-001",
        "title": "SQL Injection in login form",
        "tool": "webapp.sqli_scan",
        "affected_asset": "host1",
    }
    rerun_result = {
        "status": "completed",
        "summary": "1 finding",
        "findings": [{"title": "sql injection in login form", "severity": "critical"}],
    }
    stub = _StubExecutor(rerun_result)
    result = PatchValidator().verify_fix(finding, executor=stub)

    assert stub.calls == [("webapp.sqli_scan", "host1")]
    assert result["finding_id"] == "F-001"
    assert result["still_present"] is True
    assert result["rerun_result"]["finding_count"] == 1
    assert "verified_at" in result


def test_verify_fix_resolved_when_no_matching_finding_recurs():
    finding = {
        "id": "F-002",
        "title": "SQL Injection in login form",
        "tool": "webapp.sqli_scan",
        "affected_asset": "host1",
    }
    rerun_result = {
        "status": "no_findings",
        "summary": "clean",
        "findings": [],
    }
    stub = _StubExecutor(rerun_result)
    result = PatchValidator().verify_fix(finding, executor=stub)
    assert result["still_present"] is False


def test_verify_fix_handles_finding_missing_tool_or_asset_without_crashing():
    finding = {"id": "F-003", "title": "Something"}
    stub = _StubExecutor({"status": "completed", "findings": []})
    result = PatchValidator().verify_fix(finding, executor=stub)
    assert result["still_present"] is None
    assert stub.calls == []  # never attempted to run — nothing to run it against
