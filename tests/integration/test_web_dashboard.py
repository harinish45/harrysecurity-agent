"""
Integration tests for the NEXUS-STRIKE Strix web dashboard.
Tests cover server startup, API endpoints, and skill/agent/tool data APIs.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a test client for the dashboard FastAPI app."""
    from web.server import app
    return TestClient(app)


@pytest.fixture
def isolated_auth_vault(tmp_path, monkeypatch):
    """Redirect nexus.foundation.auth's module-level vault reference to an
    isolated per-test SecretsManager, so login tests never touch a real
    ~/.nexus install and don't leak users between tests."""
    from nexus.foundation.secrets import SecretsManager

    vault = SecretsManager(vault_dir=tmp_path)
    monkeypatch.setattr("nexus.foundation.auth.vault", vault)
    return vault


def test_dashboard_root_returns_html(client):
    """GET / should return the dashboard HTML page."""
    response = client.get("/")
    assert response.status_code == 200
    # Either the full HTML or the fallback message
    assert "NEXUS-STRIKE" in response.text


def test_api_reports_endpoint(client):
    """GET /api/reports should return a JSON object with a reports list."""
    response = client.get("/api/reports")
    assert response.status_code == 200
    data = response.json()
    assert "reports" in data
    assert isinstance(data["reports"], list)


def test_api_stats_endpoint(client):
    """GET /api/stats should return stats or a no-reports error gracefully."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    # Either has findings data or graceful error
    assert "error" in data or "total_findings" in data


def test_api_agents_endpoint(client):
    """GET /api/agents should return agent tier data."""
    response = client.get("/api/agents")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "by_tier" in data
    assert data["total"] > 0
    assert "orchestrator" in data["by_tier"]


def test_api_skills_endpoint(client):
    """GET /api/skills should return skill registry data."""
    response = client.get("/api/skills")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert data["total"] == 7  # 7 domain skills registered


def test_api_tools_endpoint(client):
    """GET /api/tools should return tool domain groupings."""
    response = client.get("/api/tools")
    assert response.status_code == 200
    data = response.json()
    assert "domains" in data
    assert "total" in data
    assert data["total"] > 0
    assert len(data["domains"]) >= 20  # 29 domains expected


def test_api_report_not_found(client):
    """GET /api/reports/nonexistent.pdf should return 404."""
    response = client.get("/api/reports/nonexistent_file_12345.pdf")
    assert response.status_code == 404


@pytest.fixture
def latest_report(tmp_path, monkeypatch):
    """Redirect REPORTS_DIR to an isolated tmp_path holding one synthetic
    JSON report — the source the mission-analysis endpoints below (MITRE
    coverage, attack graph, report-tone preview) read from."""
    import web.server as server_module

    monkeypatch.setattr(server_module, "REPORTS_DIR", tmp_path)
    report = {
        "_meta": {"target": "example.com"},
        "findings": [
            {"id": "F-1", "title": "SQL Injection", "severity": "critical", "affected_asset": "host-a",
             "tool": "webapp.sqli_scan", "evidence": "quote in param", "remediation": "parameterize queries",
             "mitre_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]},
            {"id": "F-2", "title": "Open port", "severity": "low", "affected_asset": "host-b",
             "tool": "network.port_scan"},
        ],
    }
    import json as _json
    (tmp_path / "mission.json").write_text(_json.dumps(report), encoding="utf-8")
    return tmp_path


def test_api_mitre_coverage_endpoint(client, latest_report):
    response = client.get("/api/mitre-coverage")
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "example.com"
    assert data["techniques"] == [{"id": "T1190", "name": "Exploit Public-Facing Application",
                                    "count": 1, "max_severity": "critical"}]


def test_api_mitre_coverage_empty_when_no_reports(client, tmp_path, monkeypatch):
    import web.server as server_module
    monkeypatch.setattr(server_module, "REPORTS_DIR", tmp_path / "does-not-exist")
    response = client.get("/api/mitre-coverage")
    assert response.status_code == 200
    assert response.json()["techniques"] == []


def test_api_attack_graph_endpoint(client, latest_report):
    response = client.get("/api/attack-graph")
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "example.com"
    assert "<svg" in data["svg"]
    assert data["finding_count"] == 2


def test_api_report_tone_endpoint(client, latest_report):
    response = client.get("/api/report-tone", params={"mode": "bounty"})
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "bounty"
    assert "# Bounty Report" in data["report"]


def test_api_budget_endpoint_with_no_active_mission(client):
    response = client.get("/api/budget")
    assert response.status_code == 200
    data = response.json()
    assert data["mission_id"] is None
    assert data["estimated_tokens"] == 0


def test_api_budget_endpoint_reports_a_named_mission(client):
    from nexus.foundation.guardrails.budget_guard import BudgetGuard

    BudgetGuard.reset("dash-test-mission")
    BudgetGuard.record("dash-test-mission", "x" * 400)
    response = client.get("/api/budget", params={"mission_id": "dash-test-mission"})
    assert response.status_code == 200
    data = response.json()
    assert data["estimated_tokens"] == 100
    BudgetGuard.reset("dash-test-mission")


def test_api_budget_prefers_live_subprocess_snapshot_over_local_budget_guard(client, monkeypatch):
    """Regression test: mission-mode scans run in a separate subprocess with
    their own in-memory BudgetGuard — this server process's BudgetGuard is
    never touched by them, so /api/budget always read 0 for an active
    mission-mode scan. `_stream_output` now captures each `budget_update`
    NEXUS-EVENT into `_active_scan["budget"]`; the endpoint must prefer that
    live snapshot over its own (empty) local BudgetGuard for the active
    mission."""
    import web.server as server_module
    from nexus.foundation.guardrails.budget_guard import BudgetGuard

    # This process's own BudgetGuard knows nothing about this mission —
    # simulating the real cross-process gap.
    BudgetGuard.reset("dashboard-pentest-123")

    monkeypatch.setattr(server_module, "_active_scan", {
        "process": None, "target": "example.com", "status": "running", "mode": "pentest",
        "mission_id": "dashboard-pentest-123",
        "budget": {"mission_id": "dashboard-pentest-123", "calls": 3, "estimated_tokens": 4200, "estimated_usd": 0.042},
    })

    response = client.get("/api/budget", params={"mission_id": "dashboard-pentest-123"})
    assert response.status_code == 200
    data = response.json()
    assert data["estimated_tokens"] == 4200  # from the captured subprocess snapshot, not the local (empty) BudgetGuard
    assert data["calls"] == 3


def test_api_benchmarks_endpoint_empty_when_no_history(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    response = client.get("/api/benchmarks")
    assert response.status_code == 200
    assert response.json() == {"runs": [], "total": 0}


def test_api_benchmarks_latency_endpoint_reads_history(client, tmp_path, monkeypatch):
    import json as _json

    monkeypatch.chdir(tmp_path)
    (tmp_path / "benchmarks").mkdir()
    run_1 = {"run_at": "2026-01-01T00:00:00Z", "agent_count": 2,
             "results": [{"agent": "slow_agent", "status": "completed", "latency_ms": 120.5},
                         {"agent": "fast_agent", "status": "completed", "latency_ms": 3.2}]}
    run_2 = {"run_at": "2026-01-02T00:00:00Z", "agent_count": 1,
             "results": [{"agent": "only_agent", "status": "completed", "latency_ms": 9.9}]}
    with (tmp_path / "benchmarks" / "latency_history.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(_json.dumps(run_1) + "\n")
        fh.write(_json.dumps(run_2) + "\n")

    response = client.get("/api/benchmarks/latency")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    # Newest run_at first.
    assert data["runs"][0]["run_at"] == "2026-01-02T00:00:00Z"
    assert data["runs"][1]["results"][0]["agent"] == "slow_agent"


def test_api_benchmarks_latency_endpoint_empty_when_no_history(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    response = client.get("/api/benchmarks/latency")
    assert response.status_code == 200
    assert response.json() == {"runs": [], "total": 0}


def test_api_benchmarks_latency_endpoint_tolerates_malformed_lines(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "benchmarks" / "latency_history.jsonl").write_text(
        'not json\n{"run_at": "2026-01-01T00:00:00Z", "agent_count": 0, "results": []}\n\n', encoding="utf-8"
    )
    response = client.get("/api/benchmarks/latency")
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_api_benchmarks_debate_eval_endpoint_reads_history(client, tmp_path, monkeypatch):
    import json as _json

    monkeypatch.chdir(tmp_path)
    (tmp_path / "benchmarks").mkdir()
    run = {"suite": "debate_consensus_eval", "run_at": "2026-01-01T00:00:00Z", "total_cases": 6,
           "tp": 3, "fp": 0, "fn": 0, "tn": 3, "abstained": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0,
           "predictions": []}
    (tmp_path / "benchmarks" / "debate_eval_history.jsonl").write_text(_json.dumps(run) + "\n", encoding="utf-8")

    response = client.get("/api/benchmarks/debate-eval")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["runs"][0]["f1"] == 1.0


def test_api_benchmarks_debate_eval_endpoint_empty_when_no_history(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    response = client.get("/api/benchmarks/debate-eval")
    assert response.status_code == 200
    assert response.json() == {"runs": [], "total": 0}


def test_dashboard_has_a_benchmarks_page(client):
    """The Benchmarks nav item and page must actually exist in the served
    HTML — same "don't ship a backend-only endpoint" bar as agent/run."""
    response = client.get("/")
    assert "nav-benchmarks" in response.text
    assert "page-benchmarks" in response.text
    assert "benchmarkScoreChart" in response.text


def test_dashboard_has_a_frontend_for_agent_run(client):
    """/api/agent/run existed with zero frontend until now — the Pentests
    page must actually offer a way to reach it."""
    response = client.get("/")
    assert 'id="agent-name"' in response.text
    assert 'id="agent-target"' in response.text
    assert "runAgent()" in response.text


def test_markdown_reports_are_listed_and_served(client, tmp_path, monkeypatch):
    """OrchestrationEngine._generate_report() writes .md — the reports
    list/serve endpoints used to only recognise .pdf/.json, so a mission
    report was never visible and 400'd if you guessed the URL."""
    import web.server as server

    monkeypatch.setattr(server, "REPORTS_DIR", tmp_path)
    (tmp_path / "mission-001.md").write_text("# Security Assessment Report\n", encoding="utf-8")

    listing = client.get("/api/reports")
    assert listing.status_code == 200
    names = [r["name"] for r in listing.json()["reports"]]
    assert "mission-001.md" in names

    served = client.get("/api/reports/mission-001.md")
    assert served.status_code == 200
    assert served.headers["content-type"].startswith("text/markdown")
    assert "Security Assessment Report" in served.text


def test_launch_dashboard_importable():
    """launch_dashboard function must be importable from web.server."""
    from web.server import launch_dashboard
    import inspect
    sig = inspect.signature(launch_dashboard)
    assert "host" in sig.parameters
    assert "port" in sig.parameters
    assert "open_browser" in sig.parameters


# ── Hardening regression tests ──────────────────────────────────────────

def test_security_headers_present(client):
    """Every response must carry the security headers middleware's headers."""
    response = client.get("/")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in response.headers


def test_report_path_traversal_rejected(client):
    """A traversal attempt must never escape REPORTS_DIR — same 404 as a
    plain missing file, not a 500 or (worse) file contents."""
    response = client.get("/api/reports/..%5c..%5c..%5cWindows%5cwin.ini")
    assert response.status_code == 404
    assert "detail" in response.json()


def test_scan_post_requires_csrf_header(client):
    """State-changing POSTs must reject requests missing the same-origin
    signal header, regardless of dashboard-token state."""
    response = client.post("/api/scan/stop")
    assert response.status_code == 403
    assert "X-Requested-With" in response.json()["detail"]


def test_scan_post_with_csrf_header_passes_the_gate(client):
    """With the header present, the request proceeds past the CSRF check
    (it may still no-op if there's no active scan — that's fine, the point
    here is it's not rejected at 403)."""
    response = client.post("/api/scan/stop", headers={"X-Requested-With": "NEXUS-Dashboard"})
    assert response.status_code != 403


def test_scan_start_requires_legal_ack(client, monkeypatch):
    """/api/scan/start must not auto-inject NEXUS_LEGAL_ACK — it has to
    already be set in the server's environment."""
    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)
    response = client.post(
        "/api/scan/start",
        json={"target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 403
    assert "NEXUS_LEGAL_ACK" in response.json()["detail"]


def test_scan_start_rejects_out_of_scope_target(client, monkeypatch):
    """/api/scan/start must validate the target through ScopeGuard before
    spawning anything, not rely solely on the subprocess's own executor
    chain to reject it after the fact.

    Pins NEXUS_ALLOWED_TARGETS explicitly rather than trusting whatever a
    real developer .env has configured — pydantic-settings loads .env
    directly into the shared config singleton regardless of the shell
    environment, and a broad scope there (e.g. a 0.0.0.0/0 entry left over
    from manual testing) would make this "rejected" assertion pass for the
    wrong reason (DNS resolution failure on a fake hostname) while a real,
    resolvable target would actually be let through."""
    from nexus.foundation.config import config

    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")

    response = client.post(
        "/api/scan/start",
        json={"target": "definitely-not-an-allowed-target.invalid"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 400


def test_scan_start_rejects_a_real_out_of_scope_ip(client, monkeypatch):
    """Same as above but with a literal, resolvable public IP — exercises
    the CIDR-membership check directly instead of the DNS-failure path,
    which a hostname-only test can't distinguish from a real scope block."""
    from nexus.foundation.config import config

    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")

    response = client.post(
        "/api/scan/start",
        json={"target": "8.8.8.8"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 400


def test_production_mode_requires_dashboard_token():
    """NEXUS_ENV=production with no NEXUS_DASHBOARD_TOKEN must refuse to
    start the server at all (a fresh interpreter is required since
    web.server does this check at import time)."""
    import subprocess
    import sys
    import os as _os

    env = dict(_os.environ)
    env["NEXUS_ENV"] = "production"
    env.pop("NEXUS_DASHBOARD_TOKEN", None)
    result = subprocess.run(
        [sys.executable, "-c", "import web.server"],
        cwd=_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "NEXUS_DASHBOARD_TOKEN" in result.stderr


def test_ws_steer_requires_token_when_configured():
    """/ws/steer used to have zero auth even when /ws/scan required a
    token. Both must now enforce the same check."""
    import os as _os
    import subprocess
    import sys

    env = dict(_os.environ)
    env["NEXUS_DASHBOARD_TOKEN"] = "test-token-for-ws-steer-check"
    script = (
        "import web.server as srv\n"
        "from fastapi.testclient import TestClient\n"
        "c = TestClient(srv.app)\n"
        "try:\n"
        "    with c.websocket_connect('/ws/steer'):\n"
        "        raise SystemExit(1)\n"
        "except Exception:\n"
        "    raise SystemExit(0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


# ── Per-user login / RBAC (nexus/foundation/auth.py wired into the API) ──

def test_login_with_valid_credentials_issues_a_session(client, isolated_auth_vault):
    from nexus.foundation.auth import Role, auth_manager

    auth_manager.register_user("dashtest_operator", "correct-horse-battery", Role.OPERATOR)
    response = client.post(
        "/api/auth/login",
        json={"username": "dashtest_operator", "password": "correct-horse-battery"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "dashtest_operator"
    assert data["role"] == "operator"
    assert data["token"]


def test_login_with_wrong_password_rejected(client, isolated_auth_vault):
    from nexus.foundation.auth import Role, auth_manager

    auth_manager.register_user("dashtest_wrongpw", "correct-horse-battery", Role.VIEWER)
    response = client.post(
        "/api/auth/login",
        json={"username": "dashtest_wrongpw", "password": "not-the-right-password"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 401


def test_login_requires_csrf_header(client, isolated_auth_vault):
    from nexus.foundation.auth import Role, auth_manager

    auth_manager.register_user("dashtest_csrf", "correct-horse-battery", Role.VIEWER)
    response = client.post(
        "/api/auth/login",
        json={"username": "dashtest_csrf", "password": "correct-horse-battery"},
    )
    assert response.status_code == 403


def test_login_rate_limited_across_different_usernames(client, isolated_auth_vault, monkeypatch):
    """AuthManager's per-account lockout stops a brute-force run against ONE
    username, but does nothing against a credential-spray sweeping many
    DIFFERENT usernames from the same source — each guess lands under a
    different account's own attempt counter, never tripping any single
    account's 5-attempt lockout. /api/auth/login now also applies RateGuard
    keyed by client IP, so a spray attempt gets rate-limited overall
    regardless of which username it's currently trying."""
    from nexus.foundation.guardrails.rate_guard import RateGuard

    monkeypatch.setenv("NEXUS_RATE_LIMIT", "3")
    monkeypatch.setenv("NEXUS_RATE_WINDOW", "60")
    RateGuard.reset("login:testclient")

    for i in range(3):
        response = client.post(
            "/api/auth/login",
            json={"username": f"nonexistent-user-{i}", "password": "whatever"},
            headers={"X-Requested-With": "NEXUS-Dashboard"},
        )
        assert response.status_code == 401  # under the limit, just wrong creds

    response = client.post(
        "/api/auth/login",
        json={"username": "yet-another-nonexistent-user", "password": "whatever"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 429

    RateGuard.reset("login:testclient")


def test_session_token_authenticates_api_calls(client, isolated_auth_vault):
    from nexus.foundation.auth import Role, auth_manager

    auth_manager.register_user("dashtest_me", "correct-horse-battery", Role.VIEWER)
    login = client.post(
        "/api/auth/login",
        json={"username": "dashtest_me", "password": "correct-horse-battery"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    token = login.json()["token"]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    data = me.json()
    assert data["session"] is True
    assert data["username"] == "dashtest_me"
    assert data["role"] == "viewer"


def test_viewer_role_cannot_start_a_scan(client, isolated_auth_vault):
    """A viewer-role session must be denied by real RBAC (403), distinct
    from the 401 an invalid/missing token would get."""
    from nexus.foundation.auth import Role, auth_manager

    auth_manager.register_user("dashtest_viewer_scan", "correct-horse-battery", Role.VIEWER)
    login = client.post(
        "/api/auth/login",
        json={"username": "dashtest_viewer_scan", "password": "correct-horse-battery"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    token = login.json()["token"]

    response = client.post(
        "/api/scan/start",
        json={"target": "127.0.0.1"},
        headers={"Authorization": f"Bearer {token}", "X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 403
    assert "SCAN_CREATE" in response.json()["detail"] or "scan:create" in response.json()["detail"]


def test_operator_role_passes_the_permission_check(client, isolated_auth_vault, monkeypatch):
    """An operator-role session has scan:create — the RBAC check itself
    must let it through. It may still be rejected further down the route
    for an unrelated reason (NEXUS_LEGAL_ACK not set is also a 403 in this
    route, deliberately, but a DIFFERENT one) — the point here is
    specifically that the permission check doesn't produce the
    RBAC-denied response the viewer-role test above gets."""
    from nexus.foundation.auth import Role, auth_manager

    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)
    auth_manager.register_user("dashtest_operator_scan", "correct-horse-battery", Role.OPERATOR)
    login = client.post(
        "/api/auth/login",
        json={"username": "dashtest_operator_scan", "password": "correct-horse-battery"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    token = login.json()["token"]

    response = client.post(
        "/api/scan/start",
        json={"target": "127.0.0.1"},
        headers={"Authorization": f"Bearer {token}", "X-Requested-With": "NEXUS-Dashboard"},
    )
    detail = response.json().get("detail", "")
    assert "scan:create" not in detail
    assert "lacks permission" not in detail


def test_logout_revokes_the_session(client, isolated_auth_vault):
    from nexus.foundation.auth import Role, auth_manager

    auth_manager.register_user("dashtest_logout", "correct-horse-battery", Role.VIEWER)
    login = client.post(
        "/api/auth/login",
        json={"username": "dashtest_logout", "password": "correct-horse-battery"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    token = login.json()["token"]

    logout = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}", "X-Requested-With": "NEXUS-Dashboard"})
    assert logout.status_code == 200

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    # Session revoked -> falls through to "no session" handling: either
    # open (no DASHBOARD_TOKEN configured in tests) or 401 if one is set.
    assert me.status_code in (200, 401)
    if me.status_code == 200:
        assert me.json()["session"] is False


@pytest.fixture(autouse=True)
def _pinned_scope_for_agent_run(monkeypatch):
    """Every /api/agent/run test below targets 127.0.0.1 — pin scope
    explicitly rather than trusting a real developer .env's
    NEXUS_ALLOWED_TARGETS (see test_scan_start_rejects_out_of_scope_target)."""
    from nexus.foundation.config import config

    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")


def test_agent_run_requires_csrf_header(client, monkeypatch):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    response = client.post("/api/agent/run", json={"agent": "recon_agent", "target": "127.0.0.1"})
    assert response.status_code == 403
    assert "X-Requested-With" in response.json()["detail"]


def test_agent_run_rejects_unknown_agent(client, monkeypatch):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    response = client.post(
        "/api/agent/run",
        json={"agent": "not-a-real-agent", "target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 404


def test_agent_run_requires_legal_ack(client, monkeypatch):
    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)
    response = client.post(
        "/api/agent/run",
        json={"agent": "recon_agent", "target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 403
    assert "NEXUS_LEGAL_ACK" in response.json()["detail"]


def test_agent_run_invokes_the_real_agent(client, monkeypatch):
    """End-to-end: the dashboard endpoint must actually call the named
    agent's real run(), not stub anything out."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    response = client.post(
        "/api/agent/run",
        json={"agent": "recon_agent", "target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["agent"] == "recon_agent"
    assert "findings" in body


def test_agent_run_reaches_orchestrator_tier_agents(client, monkeypatch):
    """mission_commander_agent / task_planner_agent / agent_router_agent are
    only reachable through this endpoint (and the CLI) — not through a
    mission's FlowController, since their job is planning/routing, not being
    one phase of a mission themselves."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    response = client.post(
        "/api/agent/run",
        json={"agent": "task_planner_agent", "target": "127.0.0.1", "task": "plan an assessment"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 200
    assert response.json()["agent"] == "task_planner_agent"


def test_viewer_role_cannot_run_an_agent(client, isolated_auth_vault):
    from nexus.foundation.auth import Role, auth_manager

    auth_manager.register_user("dashtest_viewer_agent", "correct-horse-battery", Role.VIEWER)
    login = client.post(
        "/api/auth/login",
        json={"username": "dashtest_viewer_agent", "password": "correct-horse-battery"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    token = login.json()["token"]

    response = client.post(
        "/api/agent/run",
        json={"agent": "recon_agent", "target": "127.0.0.1"},
        headers={"Authorization": f"Bearer {token}", "X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 403
