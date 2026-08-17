from fastapi.testclient import TestClient


def test_capability_and_workflow_endpoints_are_guarded(monkeypatch):
    monkeypatch.delenv("NEXUS_DASHBOARD_TOKEN", raising=False)
    from web.server import app

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
    monkeypatch.setenv("NEXUS_DASHBOARD_TOKEN", "secret-test-token")
    import importlib
    import web.server as server
    importlib.reload(server)

    client = TestClient(server.app)
    assert client.get("/api/capabilities").status_code == 401
    assert client.get(
        "/api/capabilities",
        headers={"Authorization": "Bearer secret-test-token"},
    ).status_code == 200
