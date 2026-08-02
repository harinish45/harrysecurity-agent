#!/usr/bin/env python3
"""
NEXUS-STRIKE — Integration Tests: Full Mission End-to-End
Verifies the orchestration engine runs end-to-end with mocked LLM.
"""
import os
import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

@pytest.fixture
def mock_llm_router():
    """Mock the LLM router to return canned, deterministic responses."""
    with patch('nexus.intelligence.llm.router.LLMRouter.complete') as mock_complete:
        mock_complete.return_value = json.dumps([
            {"agent": "recon_agent", "task": "Reconnaissance", "domain": "reconnaissance"}
        ])
        yield mock_complete

@pytest.mark.asyncio
async def test_full_mission_execution(mock_llm_router, tmp_path):
    """Test end-to-end mission execution with mocked LLM."""
    from nexus.orchestration.engine import OrchestrationEngine
    
    target = "127.0.0.1"
    mission_id = "test-mission-001"
    output_dir = str(tmp_path / "reports")
    os.makedirs(output_dir, exist_ok=True)
    
    # Mock tool execution to avoid actual network calls
    with patch('nexus.tools.executor.ToolExecutor.run') as mock_tool_run:
        mock_tool_run.return_value = {
            "tool": "reconnaissance.subdomain_enum",
            "target": target,
            "status": "no_findings",
            "findings": [],
            "summary": "No findings",
            "error": "",
            "metadata": {}
        }
        
        # Mock report generation
        with patch('nexus.reporting.generator.ReportGenerator.generate') as mock_generate:
            mock_generate.return_value = "# Test Report"
            with patch('nexus.reporting.generator.ReportGenerator.write') as mock_write:
                mock_write.return_value = os.path.join(output_dir, f"{mission_id}.json")
                
                # Run the mission
                engine = OrchestrationEngine(llm_provider="mock")
                result = await engine.run_mission(
                    target=target,
                    mission_id=mission_id,
                    mode="guided",
                    objective="full_assessment"
                )
                
                # Verify result structure
                assert result is not None, "Mission execution returned None"
                assert "findings" in result, "Mission result missing 'findings' key"
                assert "results" in result or "phases" in result, "Mission result missing execution results"
                
                # Verify the mock was called
                assert mock_llm_router.called, "LLM router was not called"