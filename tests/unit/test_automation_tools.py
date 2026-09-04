"""The 7 automation-domain tools (bash_automation, powershell_automation,
python_scripting, custom_tool_development, ai_agent_development,
security_orchestration, soar_playbooks) used to treat `target` as a local
filesystem path and read whatever file was there — an unsandboxed local
file read (CWE-22-adjacent) with no scope or path validation, reachable via
`tool_registry.run("automation.<name>", target=<any local path>)`."""
import pytest

from nexus.tools.automation import (
    ai_agent_development,
    bash_automation,
    custom_tool_development,
    powershell_automation,
    python_scripting,
    security_orchestration,
    soar_playbooks,
)

MODULES = [
    ai_agent_development, bash_automation, custom_tool_development,
    powershell_automation, python_scripting, security_orchestration, soar_playbooks,
]


@pytest.mark.parametrize("module", MODULES, ids=[m.__name__ for m in MODULES])
def test_does_not_read_a_local_file_even_when_target_is_a_real_path(module, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("top-secret-content-should-never-appear-in-findings", encoding="utf-8")

    result = module.run(target=str(secret_file))

    assert result["status"] == "completed"
    joined = " ".join(str(f) for f in result["findings"])
    assert "top-secret-content" not in joined
    assert "File size" not in joined
