"""Regression tests for dashboard security boundaries."""

import pytest
from fastapi.testclient import TestClient

import web.server as server
from nexus.foundation.config import config


def test_websocket_auth_check_requires_token_when_configured(monkeypatch):
    class Headers:
        def get(self, key, default=""):
            return "" if key == "Authorization" else default

    class WebSocket:
        headers = Headers()

    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "secret")
    assert not server._websocket_auth_check(WebSocket(), {})
    assert server._websocket_auth_check(WebSocket(), {"token": "secret"})


def test_websocket_auth_check_allows_bearer_header(monkeypatch):
    class Headers:
        def get(self, key, default=""):
            return "Bearer secret" if key == "Authorization" else default

    class WebSocket:
        headers = Headers()

    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "secret")
    assert server._websocket_auth_check(WebSocket(), {})


def test_scan_start_rejects_out_of_scope_target(monkeypatch):
    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost,127.0.0.1,::1")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")

    client = TestClient(server.app)
    # scan_start also enforces a same-origin CSRF check (require_same_origin_signal)
    # ahead of the guardrail/authorization checks these tests exercise — every
    # request here needs the header to reach the behavior actually under test.
    response = client.post(
        "/api/scan/start", json={"target": "example.com"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    # scan_start's real behavior: ScopeGuard rejection surfaces as 400
    # "Target rejected: ..." (an invalid request), not a 403 "guardrail
    # blocked" — matches the ScopeGuard.validate() call site in web/server.py.
    assert response.status_code == 400
    assert "outside the configured scope" in response.json()["detail"].lower()


def test_scan_start_rejects_without_authorization(monkeypatch):
    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost")
    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)

    client = TestClient(server.app)
    response = client.post(
        "/api/scan/start", json={"target": "localhost"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 403
    assert "authorization" in response.json()["detail"].lower()


def test_scan_start_does_not_inject_authorization_into_subprocess(monkeypatch):
    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")

    captured = {}

    class FakeProcess:
        pid = 1234
        stdout = []

        def poll(self):
            return 0

    def fake_popen(cmd, **kwargs):
        captured.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(server._subprocess, "Popen", fake_popen)
    client = TestClient(server.app)
    response = client.post(
        "/api/scan/start", json={"target": "localhost"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 200
    assert captured["env"].get("NEXUS_LEGAL_ACK") == "I_HAVE_WRITTEN_AUTHORIZATION"
    # The value must come from the caller's environment, not be synthesized by the endpoint.


def test_launch_dashboard_does_not_trust_proxy_headers_by_default(monkeypatch):
    """uvicorn's own defaults (proxy_headers=True, forwarded_allow_ips=
    '127.0.0.1') let anything connecting from the loopback interface spoof
    request.client via X-Forwarded-For, which RateGuard then keys its
    per-IP rate limit off of. launch_dashboard() must override those
    defaults to not-trusted unless the operator opts in."""
    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "secret")
    monkeypatch.delenv("NEXUS_TRUST_PROXY_HEADERS", raising=False)
    monkeypatch.setattr(server, "TRUST_PROXY_HEADERS", False)

    captured = {}

    def fake_run(app, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(server.uvicorn, "run", fake_run)
    monkeypatch.setattr(server.threading, "Timer", lambda *a, **k: type("T", (), {"start": lambda self: None})())

    server.launch_dashboard(host="127.0.0.1", port=8765, open_browser=False)

    assert captured["proxy_headers"] is False
    assert captured["forwarded_allow_ips"] == []


def test_launch_dashboard_trusts_proxy_headers_when_opted_in(monkeypatch):
    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "secret")
    monkeypatch.setattr(server, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(server, "TRUSTED_PROXY_IPS", "10.0.0.5")

    captured = {}

    def fake_run(app, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(server.uvicorn, "run", fake_run)
    monkeypatch.setattr(server.threading, "Timer", lambda *a, **k: type("T", (), {"start": lambda self: None})())

    server.launch_dashboard(host="127.0.0.1", port=8765, open_browser=False)

    assert captured["proxy_headers"] is True
    assert captured["forwarded_allow_ips"] == "10.0.0.5"
