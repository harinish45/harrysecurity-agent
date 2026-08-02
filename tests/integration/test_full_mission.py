#!/usr/bin/env python3
"""
NEXUS-STRIKE — Integration Tests: Full Mission End-to-End
Verifies the orchestration engine runs end-to-end with mocked LLM.
"""
import os
import json
import pytest
from unittest.mock import patch, MagicMock

# Ensure reports directory exists for the test
os.makedirs("reports", exist_ok=True)

@pytest.fixture
def mock_llm_router():
    """Mock the LLM router to return canned, deterministic responses."""
    with patch('nexus.llm.router.route') as mock_route:
        mock_route.return_value = {
            "action": "run_tool",
            "tool": "webapp.sqli",
            "reasoning": "Testing SQL injection on target."
        }
        yield mock_route

def test_full_mission_execution(mock_llm_router, tmp_path):
    """Test end-to-end mission execution with mocked LLM."""
    from nexus.orchestration.engine import run_mission
    
    target = "127.0.0.1"
    mission_id = "test-mission-001"
    output_dir = str(tmp_path / "reports")
    os.makedirs(output_dir, exist_ok=True)
    
    # Run the mission
    result = run_mission(
        target=target,
        mission_id=mission_id,
        output_dir=output_dir,
        non_interactive=True
    )
    
    # Verify result structure
    assert result is not None, "Mission execution returned None"
    assert "findings" in result, "Mission result missing 'findings' key"
    assert "phases" in result, "Mission result missing 'phases' key"
    
    # Verify JSON output file was created
    json_files = [f for f in os.listdir(output_dir) if f.endswith('.json') and mission_id in f]
    assert len(json_files) > 0, f"No JSON output file found for mission {mission_id} in {output_dir}"
    
    # Verify JSON content
    output_file = os.path.join(output_dir, json_files[0])
    with open(output_file, 'r') as f:
        saved_result = json.load(f)
        
    assert "findings" in saved_result, "Saved JSON missing 'findings' key"
    assert "phases" in saved_result, "Saved JSON missing 'phases' key"
    assert saved_result.get("target") == target, "Saved JSON target mismatch"