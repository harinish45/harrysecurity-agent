from nexus.advanced.threat_modeling import ThreatModeler


def _f(asset, title, severity="medium", tool="network.port_scan"):
    return {"affected_asset": asset, "title": title, "severity": severity, "tool": tool}


def test_empty_input_returns_empty_list():
    assert ThreatModeler().predict_attack_paths([]) == []


def test_single_node_graph_does_not_crash():
    findings = [_f("host1", "Open port 22", severity="low")]
    results = ThreatModeler().predict_attack_paths(findings)
    assert len(results) == 1
    assert results[0]["path"] == ["host1"]
    assert results[0]["risk_score"] >= 0


def test_no_critical_assets_ranks_all_nodes_by_score():
    findings = [
        _f("db01", "SQL injection", severity="critical", tool="webapp.sqli"),
        _f("db01", "Weak TLS config", severity="low", tool="network.tls_scan"),
        _f("host2", "Info disclosure", severity="info", tool="network.tls_scan"),
    ]
    results = ThreatModeler().predict_attack_paths(findings)
    nodes = {r["path"][0] for r in results}
    assert nodes == {"db01", "host2"}
    # db01 has a critical finding, should outrank host2's info-only finding
    scores = {r["path"][0]: r["risk_score"] for r in results}
    assert scores["db01"] > scores["host2"]


def test_shortest_path_to_critical_asset():
    # host1 and db01 share the "network" tool domain -> edge host1->db01
    findings = [
        _f("host1", "Open port 22", severity="low", tool="network.port_scan"),
        _f("db01", "Weak TLS config", severity="high", tool="network.tls_scan"),
    ]
    results = ThreatModeler().predict_attack_paths(findings, critical_assets=["db01"])
    assert len(results) == 1
    assert results[0]["path"] == ["host1", "db01"]
    assert results[0]["risk_score"] > 0
    assert "rationale" in results[0]


def test_rule_bonus_for_auth_plus_open_service():
    # Equal severity totals (medium+medium=4 each) so the only difference
    # in score is the Rule 1 auth+open-service bonus.
    findings_with_bonus = [
        _f("host1", "Login page auth bypass", severity="medium", tool="webapp.auth"),
        _f("host1", "Open port detected on 8080", severity="medium", tool="webapp.auth"),
    ]
    findings_without_bonus = [
        _f("host2", "Login page auth bypass", severity="medium", tool="webapp.auth"),
        _f("host2", "Session token exposed in URL", severity="medium", tool="webapp.auth"),
    ]
    combined = findings_with_bonus + findings_without_bonus
    results = ThreatModeler().predict_attack_paths(combined)
    scores = {r["path"][0]: r["risk_score"] for r in results}
    # host1 gets the auth+open-service rule bonus; host2 (auth-only) doesn't.
    assert scores["host1"] > scores["host2"]


def test_no_path_to_unreachable_critical_asset_is_omitted_not_crashed():
    findings = [
        _f("isolated1", "Something", severity="low", tool="network.scan"),
        _f("critical1", "Something else", severity="high", tool="webapp.scan"),
    ]
    results = ThreatModeler().predict_attack_paths(findings, critical_assets=["critical1"])
    # No shared tool domain -> no edge -> no path found -> empty, not a crash.
    assert results == []
