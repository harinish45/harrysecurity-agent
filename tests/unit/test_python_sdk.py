"""nexus/interface/sdk/python_sdk.py was a literal 1-line stub
(`return {'status': 'stub'}`) — not advertised anywhere as more than that,
but there's no reason it can't be a real, thin wrapper around
OrchestrationEngine.run_mission() now that FlowController makes that engine
worth embedding."""
import pytest

from nexus.interface.sdk.python_sdk import NexusSDK


@pytest.mark.asyncio
async def test_run_mission_delegates_to_the_real_engine(monkeypatch):
    calls = {}

    async def fake_run_mission(self, **kwargs):
        calls.update(kwargs)
        return {"status": "completed", "target": kwargs["target"]}

    from nexus.orchestration.engine import OrchestrationEngine
    monkeypatch.setattr(OrchestrationEngine, "run_mission", fake_run_mission)

    sdk = NexusSDK()
    result = await sdk.run_mission("127.0.0.1", mission_id="test-sdk")

    assert result == {"status": "completed", "target": "127.0.0.1"}
    assert calls["target"] == "127.0.0.1"
    assert calls["mission_id"] == "test-sdk"


def test_run_mission_sync_wraps_the_async_call(monkeypatch):
    async def fake_run_mission(self, **kwargs):
        return {"status": "completed", "target": kwargs["target"]}

    from nexus.orchestration.engine import OrchestrationEngine
    monkeypatch.setattr(OrchestrationEngine, "run_mission", fake_run_mission)

    result = NexusSDK().run_mission_sync("127.0.0.1")
    assert result["status"] == "completed"
