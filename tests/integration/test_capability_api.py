from fastapi.testclient import TestClient


def test_capability_and_workflow_endpoints_are_guarded(monkeypatch):
    from web.server import app

    monkeypatch.setattr("web.server.DASHBOARD_TOKEN", "")
    client = TestClient(app)
    capabilities = client.get("/api/capabilities")
    workflows = client.get("/api/workflows")

    assert capabilities.status_code == 200
    payload = capabilities.json()
    assert payload["coverage"]["total"] >= 70
    assert any(item["key"] == "agent.api_security" for item in payload["matrix"])

    assert workflows.status_code == 200
    workflow_payload = workflows.json()
    modes = {item["mode"] for item in workflow_payload["workflows"]}
    assert {"pentest", "purple_team", "vulnerability_research", "ctf", "research"}.issubset(modes)


def test_capability_endpoint_requires_dashboard_token(monkeypatch):
    import web.server as server

    monkeypatch.setattr(server, "DASHBOARD_TOKEN", "secret-test-token")
    client = TestClient(server.app)
    assert client.get("/api/capabilities").status_code == 401
    assert client.get(
        "/api/capabilities",
        headers={"Authorization": "Bearer secret-test-token"},
    ).status_code == 200
