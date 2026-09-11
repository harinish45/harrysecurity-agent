"""Regression tests for web/mission_api.py.

Historically nexus/mission/service.py (defining MissionService) went missing
from the working tree while web/mission_api.py still imported it, so the
module could not even be imported -- `import web.mission_api` raised:

    ImportError: cannot import name 'MissionService' from 'nexus.mission'

That failure was latent only because web/server.py never mounted
mission_api's router; restoring that one-line `include_router` would have
crashed the dashboard process on startup. These tests import the module and
exercise its FastAPI routes end-to-end to guard against regressions in
either the import wiring or the MissionService <-> mission_api contract
(e.g. the /events endpoint's use of `event.event_type` / `event.sequence`,
fields MissionEvent itself does not have).
"""
from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_mission_api_module_imports_cleanly():
    """The module-level `from nexus.mission import ... MissionService` must resolve."""
    module = importlib.import_module("web.mission_api")
    importlib.reload(module)  # ensure a fresh _service bound to the current env var
    assert hasattr(module, "MissionService")
    assert hasattr(module, "router")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_MISSIONS_DIR", str(tmp_path / "missions"))
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.delenv("NEXUS_DASHBOARD_TOKEN", raising=False)

    import web.mission_api as mission_api

    importlib.reload(mission_api)  # rebind _service to the tmp_path mission dir

    app = FastAPI()
    app.include_router(mission_api.router)
    return TestClient(app)


def test_create_list_get_transition_and_replay_round_trip(client):
    created = client.post(
        "/api/missions",
        json={"target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert created.status_code == 200
    body = created.json()
    mission_id = body["mission_id"]
    assert body["target"] == "127.0.0.1"
    assert body["status"] == "created"

    listed = client.get("/api/missions")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    fetched = client.get(f"/api/missions/{mission_id}")
    assert fetched.status_code == 200
    assert fetched.json()["mission"]["mission_id"] == mission_id

    transitioned = client.post(
        f"/api/missions/{mission_id}/transition",
        json={"status": "authorized", "actor": "operator", "reason": "written authorization"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert transitioned.status_code == 200
    assert transitioned.json()["status"] == "authorized"

    events = client.get(f"/api/missions/{mission_id}/events")
    assert events.status_code == 200
    payload = events.json()
    assert payload["mission_id"] == mission_id
    assert len(payload["events"]) >= 2
    for index, event in enumerate(payload["events"], start=1):
        assert event["sequence"] == index
        assert event["event_type"]  # non-empty string, not the raw `.type` attr error


def test_get_missing_mission_returns_404(client):
    response = client.get("/api/missions/does-not-exist")
    assert response.status_code == 404
