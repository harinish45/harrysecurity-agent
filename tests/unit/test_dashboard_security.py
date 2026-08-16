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
    response = client.post("/api/scan/start", json={"target": "example.com"})
    assert response.status_code == 403
    assert "guardrail" in response.json()["detail"].lower()


def test_scan_start_rejects_without_authorization(monkeypatch):
    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost")
    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)

    client = TestClient(server.app)
    response = client.post("/api/scan/start", json={"target": "localhost"})
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
    response = client.post("/api/scan/start", json={"target": "localhost"})
    assert response.status_code == 200
    assert captured["env"].get("NEXUS_LEGAL_ACK") == "I_HAVE_WRITTEN_AUTHORIZATION"
    # The value must come from the caller's environment, not be synthesized by the endpoint.
