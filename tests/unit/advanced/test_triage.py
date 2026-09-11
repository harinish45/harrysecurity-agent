from nexus.advanced.triage import Triage


def _f(id_, title, severity, confidence, asset="host1", references=None):
    return {
        "id": id_,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "affected_asset": asset,
        "references": references or [],
    }


def test_prioritize_orders_by_severity_and_confidence():
    findings = [
        _f("F-1", "Low issue", "low", "certain"),
        _f("F-2", "Critical issue", "critical", "certain"),
        _f("F-3", "Medium issue, tentative", "medium", "tentative"),
    ]
    result = Triage().prioritize(findings)
    assert [f["id"] for f in result] == ["F-2", "F-1", "F-3"]
    assert all("priority_score" in f for f in result)
    # original fields untouched
    assert result[0]["severity"] == "critical"
    assert result[0]["confidence"] == "certain"


def test_prioritize_applies_critical_asset_bonus():
    findings = [
        _f("F-1", "Issue on ordinary host", "medium", "high", asset="host1"),
        _f("F-2", "Issue on crown jewel", "medium", "high", asset="db-prod"),
    ]
    result = Triage().prioritize(findings, critical_assets=["db-prod"])
    assert result[0]["id"] == "F-2"
    assert result[0]["priority_score"] > result[1]["priority_score"]


def test_deduplicate_merges_near_duplicates_and_keeps_references():
    findings = [
        _f("F-1", "SQL Injection in login form", "high", "high", asset="host1", references=["CVE-2021-1"]),
        _f("F-2", "sql injection in login form", "critical", "certain", asset="host1", references=["CWE-89"]),
        _f("F-3", "Unrelated XSS issue", "medium", "medium", asset="host1"),
    ]
    result = Triage().deduplicate(findings)
    assert len(result) == 2
    merged = next(f for f in result if "SQL" in f["title"] or "sql" in f["title"])
    assert merged["id"] == "F-2"  # higher severity/confidence kept
    assert set(merged["references"]) == {"CVE-2021-1", "CWE-89"}


def test_deduplicate_keeps_findings_on_different_assets_separate():
    findings = [
        _f("F-1", "Open port 22", "low", "high", asset="host1"),
        _f("F-2", "Open port 22", "low", "high", asset="host2"),
    ]
    result = Triage().deduplicate(findings)
    assert len(result) == 2
