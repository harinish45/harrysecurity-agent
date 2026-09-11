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


def test_stale_budget_update_from_a_superseded_scans_reader_thread_does_not_clobber_active_mission(client, monkeypatch):
    """Regression test for a race in `_stream_output` (web/server.py):
    its background reader thread keeps consuming buffered subprocess
    stdout even after `_active_scan` has moved on to a new mission — e.g.
    an operator calls POST /api/scan/stop immediately followed by
    POST /api/scan/start. Unlike the final-status write a few lines below
    it (`if _active_scan.get("process") is process: ...`), the
    `budget_update` handler used to write `_active_scan["budget"]`
    unconditionally, with no check that the event actually belonged to
    the process/mission `_active_scan` currently tracks.

    This spawns the real `scan_start` route (with `subprocess.Popen`
    faked out) so it exercises the actual production `_stream_output`
    thread, not a reimplementation of its logic.
    """
    import threading
    import time
    import web.server as server_module

    original_active_scan = dict(server_module._active_scan)
    release_stale_line = threading.Event()

    class FakeOldProcess:
        pid = 111

        def __init__(self):
            self._terminated = False

        def poll(self):
            # Mirrors real life: the OS reports the process as exited
            # almost immediately after terminate(), well before its
            # stdout reader thread has necessarily drained every
            # buffered line.
            return 0 if self._terminated else None

        def terminate(self):
            self._terminated = True

        @property
        def stdout(self):
            # Blocks here to simulate the reader thread still being
            # mid-loop, catching up on buffered output, when the new
            # scan starts below.
            release_stale_line.wait(timeout=5)
            yield (
                'NEXUS-EVENT:{"type": "budget_update", "mission_id": "old-mission", '
                '"calls": 999, "estimated_tokens": 999999, "estimated_usd": 9.99}'
            )

        def wait(self):
            return 0

    class FakeNewProcess:
        pid = 222

        def poll(self):
            return None

        @property
        def stdout(self):
            return iter([])

        def wait(self):
            return 0

        def terminate(self):
            pass

    fake_procs = [FakeOldProcess(), FakeNewProcess()]
    monkeypatch.setattr(server_module._subprocess, "Popen", lambda *a, **k: fake_procs.pop(0))
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")

    try:
        r1 = client.post(
            "/api/scan/start",
            json={"target": "127.0.0.1", "mode": "pentest"},
            headers={"X-Requested-With": "NEXUS-Dashboard"},
        )
        assert r1.status_code == 200
        # _stream_output's thread for the old scan is now alive and
        # blocked inside FakeOldProcess.stdout, waiting on the Event.
        old_mission_id = server_module._active_scan.get("mission_id")
        assert old_mission_id

        client.post("/api/scan/stop", headers={"X-Requested-With": "NEXUS-Dashboard"})

        r2 = client.post(
            "/api/scan/start",
            json={"target": "127.0.0.1", "mode": "bounty"},
            headers={"X-Requested-With": "NEXUS-Dashboard"},
        )
        assert r2.status_code == 200
        new_mission_id = server_module._active_scan.get("mission_id")
        assert new_mission_id and new_mission_id != old_mission_id

        # Now let the OLD subprocess's reader thread deliver its stale
        # budget_update line, well after _active_scan has moved on.
        release_stale_line.set()
        for _ in range(50):  # give the background thread time to run
            time.sleep(0.02)
            if server_module._active_scan.get("budget") is not None:
                break

        assert server_module._active_scan.get("mission_id") == new_mission_id
        stale_budget = server_module._active_scan.get("budget")
        assert stale_budget is None or stale_budget.get("mission_id") != "old-mission"
    finally:
        server_module._active_scan = original_active_scan


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


@pytest.mark.asyncio
async def test_concurrent_scan_start_requests_do_not_orphan_a_process(monkeypatch):
    """Regression test: /api/scan/start did a check-then-act on the shared
    module-level _active_scan dict with a real `await` (broadcasting to
    connected WS clients) sitting between the "already running?" check and
    the point _active_scan is actually populated with the new subprocess
    handle. Two concurrent POSTs could both pass the check while
    _active_scan still looked idle/"starting", both call subprocess.Popen,
    and both overwrite _active_scan — orphaning whichever process lost the
    race (invisible to /api/scan/status and /api/scan/stop forever after).

    This drives two real concurrent requests through the actual ASGI app
    (not TestClient's synchronous wrapper) with a WS client stand-in whose
    send_json() genuinely suspends, exactly like the awaited broadcast in
    the real bug, to prove the added _active_scan_lock closes the window:
    exactly one request must reach Popen() and get "started"; the other
    must see "already_running"."""
    import asyncio

    import web.server as server_module
    from nexus.foundation.config import config

    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    monkeypatch.setattr(server_module, "_active_scan", {"process": None, "target": None, "status": "idle"})

    popen_calls = []

    class FakeProc:
        def __init__(self):
            self.pid = 4242
            self.stdout = iter([])  # no output lines -> reader thread exits immediately

        def poll(self):
            return None

        def wait(self):
            return 0

        def terminate(self):
            pass

    def fake_popen(*args, **kwargs):
        popen_calls.append((args, kwargs))
        return FakeProc()

    monkeypatch.setattr(server_module._subprocess, "Popen", fake_popen)

    class SlowWSClient:
        """Stands in for a real connected dashboard WS client: send_json()
        genuinely suspends the coroutine, the same way `await
        ws.send_json(event)` does for a real socket — this is what turns
        the broadcast inside scan_start into a real interleaving point."""

        async def send_json(self, event):
            await asyncio.sleep(0.05)

    monkeypatch.setattr(server_module, "_ws_clients", [SlowWSClient()])

    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=server_module.app)
    headers = {"X-Requested-With": "NEXUS-Dashboard"}
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        response_a, response_b = await asyncio.gather(
            ac.post("/api/scan/start", json={"target": "127.0.0.1"}, headers=headers),
            ac.post("/api/scan/start", json={"target": "127.0.0.1"}, headers=headers),
        )

    statuses = sorted(r.json()["status"] for r in (response_a, response_b))
    assert statuses == ["already_running", "started"]
    # The critical assertion: only the winner of the race ever reaches
    # Popen() -- before the fix, both requests spawned a subprocess and the
    # loser's process/handle was silently dropped on the floor.
    assert len(popen_calls) == 1


def test_scan_start_rejects_unhashable_mode_with_400(client, monkeypatch):
    """Regression test: a non-string `mode` (e.g. a JSON array or object)
    used to blow past the `mode != "live"` check straight into
    `mode not in _MISSION_MODES` — membership-testing an unhashable value
    against that set raised an uncaught `TypeError`, turning a malformed
    request into a generic 500 instead of the clean 400 every other bad
    `mode`/target path returns. It must now come back as a 400 for both
    a list and a dict payload."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")

    for bad_mode in [["x"], {}]:
        response = client.post(
            "/api/scan/start",
            json={"target": "127.0.0.1", "mode": bad_mode},
            headers={"X-Requested-With": "NEXUS-Dashboard"},
        )
        assert response.status_code == 400
        assert "Unknown mode" in response.json()["detail"]


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


def test_ws_scan_rejects_oversized_message(client):
    """Regression test: neither /ws/scan nor /ws/steer used to impose any
    application-level cap on an incoming message before calling
    receive_text(), relying entirely on uvicorn's transport-level
    ws_max_size (never overridden by launch_dashboard()'s uvicorn.run()).
    A client streaming large frames could drive server memory up with no
    circuit breaker. The handler must now reject an over-cap message by
    closing the connection instead of echoing it back."""
    from web.server import MAX_WS_MESSAGE_BYTES

    oversized = "x" * (MAX_WS_MESSAGE_BYTES + 1)
    with client.websocket_connect("/ws/scan") as ws:
        ws.receive_json()  # initial status message sent on connect
        ws.send_text(oversized)
        # The server must close the connection rather than ack the
        # oversized payload back to the client.
        with pytest.raises(Exception):
            ws.receive_json()


def test_ws_steer_rejects_oversized_message(client):
    """Same cap, enforced on /ws/steer."""
    from web.server import MAX_WS_MESSAGE_BYTES

    oversized = "x" * (MAX_WS_MESSAGE_BYTES + 1)
    with client.websocket_connect("/ws/steer") as ws:
        ws.send_text(oversized)
        with pytest.raises(Exception):
            ws.receive_text()


def test_ws_scan_acks_message_within_cap(client):
    """Sanity check: a normal, within-cap message still gets echoed back
    as before — the cap must not reject legitimate traffic."""
    with client.websocket_connect("/ws/scan") as ws:
        ws.receive_json()  # initial status message sent on connect
        ws.send_text("hello")
        response = ws.receive_json()
        assert response == {"type": "ack", "message": "hello"}


def test_ws_scan_enforces_max_connections(monkeypatch):
    """/ws/scan used to accept an unbounded number of concurrent
    connections — no cap in the handler and no `limit_concurrency` on
    uvicorn.run(). Any client that can reach the port (the no-token dev
    default) could open thousands of connections in a loop, each holding
    an OS socket fd + asyncio task, exhausting the server's fd limit and
    taking the whole dashboard down (EMFILE) for everyone else. A
    connection beyond WS_MAX_CONNECTIONS must now be rejected before being
    accepted, and accepted clients must still be tracked correctly."""
    import web.server as server

    monkeypatch.setattr(server, "WS_MAX_CONNECTIONS", 2)
    # _ws_clients is a set (.add()/.discard() are used on it in the real
    # handler) — a plain list here would AttributeError the moment a real
    # connection tries to register itself.
    monkeypatch.setattr(server, "_ws_clients", set())
    client = TestClient(server.app)

    with client.websocket_connect("/ws/scan") as ws1:
        ws1.receive_json()  # initial status message
        with client.websocket_connect("/ws/scan") as ws2:
            ws2.receive_json()
            assert len(server._ws_clients) == 2

            # A third connection is over the cap and must be refused.
            with pytest.raises(Exception):
                with client.websocket_connect("/ws/scan") as ws3:
                    ws3.receive_json()

            # The rejected connection must not have been counted, and the
            # two legitimately-accepted clients must remain intact.
            assert len(server._ws_clients) == 2


def test_ws_steer_enforces_max_connections(monkeypatch):
    """/ws/steer has no client list to broadcast through, but it must
    still be capped independently — otherwise it's an uncapped second
    attack surface for the same fd-exhaustion DoS as /ws/scan."""
    import web.server as server

    monkeypatch.setattr(server, "WS_MAX_CONNECTIONS", 1)
    monkeypatch.setattr(server, "_ws_steer_count", 0)
    client = TestClient(server.app)

    with client.websocket_connect("/ws/steer"):
        assert server._ws_steer_count == 1
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/steer"):
                pass
        # the rejected attempt must not have incremented the counter
        assert server._ws_steer_count == 1


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


# ── Request body size cap (unauthenticated-DoS hardening) ───────────────

def test_oversized_body_rejected_before_auth_check(client):
    """A large JSON body posted to a `payload: dict` route with NO
    Authorization header at all must be rejected with 413 by the body-size
    cap, not parsed first and then hit the (unrelated) auth/CSRF checks.
    Regression test for: FastAPI resolves `payload: dict` via dependency
    injection before the route body — and therefore before
    `_require_token()` — ever runs, so an unauthenticated caller could
    previously force the server to buffer/decode an arbitrarily large body
    in memory before any check rejected it."""
    huge = "x" * (3 * 1024 * 1024)  # 3 MiB, over the 2 MiB default cap
    response = client.post("/api/scan/start", json={"target": huge})
    assert response.status_code == 413
    assert "too large" in response.json()["detail"].lower()


def test_oversized_body_rejected_on_every_payload_route(client):
    """Same cap applies to every `payload: dict` route, not just one."""
    huge_payload = {"x": "y" * (3 * 1024 * 1024)}
    for path in ("/api/auth/login", "/api/config", "/api/scan/start", "/api/agent/run"):
        response = client.post(path, json=huge_payload)
        assert response.status_code == 413, f"{path} did not enforce the body-size cap"


def test_small_body_still_reaches_the_normal_csrf_check(client):
    """Sanity check the cap isn't overly aggressive: a small, legitimate
    body must NOT be rejected by the size limit — it should proceed to the
    route's own checks (here, the CSRF header check) exactly as before."""
    response = client.post("/api/scan/start", json={"target": "127.0.0.1"})
    assert response.status_code == 403
    assert "X-Requested-With" in response.json()["detail"]


def test_max_body_size_middleware_enforces_cap_without_content_length():
    """Direct ASGI-level test of the streaming enforcement path: a request
    with no Content-Length header at all (e.g. chunked transfer) must still
    be capped as the body streams in, not just when Content-Length is
    present and honest."""
    import anyio
    from web.middleware import MaxBodySizeMiddleware

    async def downstream_app(scope, receive, send):
        # Drain the body exactly like Starlette's request.body() would.
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    middleware = MaxBodySizeMiddleware(downstream_app, max_body_size=10)

    scope = {"type": "http", "headers": []}  # no content-length header
    chunks = [b"a" * 5, b"b" * 5, b"c" * 5]  # 15 bytes total, over the 10-byte cap

    async def receive():
        if chunks:
            body = chunks.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(chunks)}
        return {"type": "http.disconnect"}

    sent = []

    async def send(message):
        sent.append(message)

    async def run():
        await middleware(scope, receive, send)

    anyio.run(run)

    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413


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


# ── Mission-control API mounting ──────────────────────────────────────────
# Regression coverage for the mission-control router actually being wired
# into this app. web/mission_api.py defines a full APIRouter
# (create/list/get/transition/replay missions under /api/missions) with its
# own passing unit tests for the underlying Mission model
# (tests/unit/test_mission.py), but web/server.py never called
# `app.include_router(mission_router)` — every /api/missions/* request
# 404'd from *this* app regardless of payload or auth, since FastAPI had no
# route registered for that path at all. These tests exercise the mounted
# router end-to-end through the real `client` fixture (i.e. through
# `web.server.app`) so a future regression that drops the include_router
# call again fails here with a 404, not just in mission_api's own
# in-isolation unit tests.


@pytest.fixture
def isolated_mission_service(tmp_path, monkeypatch):
    """Point the mission-control API at an isolated mission store so these
    tests never read/write the real engagements/missions directory."""
    import web.mission_api as mission_api
    from nexus.mission import MissionService, MissionStore

    service = MissionService(MissionStore(tmp_path))
    monkeypatch.setattr(mission_api, "_service", service)
    return service


@pytest.fixture
def mission_scope(monkeypatch):
    """Satisfy ScopeGuard/LegalGuard for a 127.0.0.1 target the same way
    test_dashboard_security.py's scan_start tests do."""
    from nexus.foundation.config import config

    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")


def test_mission_router_is_mounted_and_reachable(client, isolated_mission_service, mission_scope):
    """POST/GET /api/missions must resolve to mission_api's handlers, not a
    404 from an unmounted router."""
    create_response = client.post(
        "/api/missions",
        json={"target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["target"] == "127.0.0.1"
    assert created["status"] == "created"
    mission_id = created["mission_id"]

    list_response = client.get("/api/missions")
    assert list_response.status_code == 200
    listing = list_response.json()
    assert listing["total"] == 1
    assert listing["missions"][0]["mission_id"] == mission_id

    get_response = client.get(f"/api/missions/{mission_id}")
    assert get_response.status_code == 200
    assert get_response.json()["mission"]["mission_id"] == mission_id


def test_mission_router_requires_dashboard_token_when_configured(client, isolated_mission_service, mission_scope, monkeypatch):
    """mission_api delegates its auth check to web.server's own
    _require_token/_require_permission (same DASHBOARD_TOKEN constant and
    per-user RBAC as every other /api/* route) instead of maintaining a
    second, independent implementation — mounting the router must not
    implicitly expose it to unauthenticated callers once an operator has
    configured a dashboard token. DASHBOARD_TOKEN is a module constant read
    once at import time, so it's set via monkeypatch.setattr on the module
    (matching test_dashboard_security.py's pattern), not via setenv."""
    import web.server as server

    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "secret-token")

    unauthenticated = client.post(
        "/api/missions",
        json={"target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert unauthenticated.status_code == 401

    authenticated = client.post(
        "/api/missions",
        json={"target": "127.0.0.1"},
        headers={"Authorization": "Bearer secret-token", "X-Requested-With": "NEXUS-Dashboard"},
    )
    assert authenticated.status_code == 200
