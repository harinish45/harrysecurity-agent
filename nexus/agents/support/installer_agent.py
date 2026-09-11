from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class InstallerAgent(BaseAgent):
    name = "installer_agent"
    description = "support agent for installation — installs dependencies, configures environments, and sets up tools"

    # Only packages actually relevant to a keyword in `task` are ever
    # installed — this agent used to unconditionally `pip install` a
    # 14-package list on every single invocation regardless of what the
    # task asked for, unlike every sibling support agent (which all gate
    # real work behind a keyword/relevance check on `task`).
    _KEYWORD_PACKAGES = {
        "network": ["scapy", "python-nmap"], "scan": ["scapy", "python-nmap"],
        "web": ["requests", "flask"], "http": ["requests"], "api": ["requests", "fastapi"],
        "crypto": ["cryptography", "pyopenssl"], "tls": ["cryptography", "pyopenssl"],
        "database": ["sqlalchemy"], "orm": ["sqlalchemy"],
        "django": ["django"],
        "test": ["pytest"], "lint": ["black", "flake8", "mypy"],
        "env": ["python-dotenv"], "config": ["python-dotenv"],
    }

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        installed = []
        skipped = []
        failed = []
        tools_used = []

        task_lower = task.lower()
        relevant_packages = sorted({
            pkg for kw, pkgs in self._KEYWORD_PACKAGES.items() if kw in task_lower for pkg in pkgs
        })

        if not relevant_packages:
            skipped.append({"reason": f"no package-relevant keyword found in task; nothing installed"})
        for pkg in relevant_packages:
            try:
                __import__(pkg.replace("-", "_"))
                skipped.append({"package": pkg, "reason": "already installed"})
            except ImportError:
                try:
                    import subprocess
                    result = subprocess.run(
                        ["pip", "install", pkg],
                        capture_output=True, text=True, timeout=120,
                    )
                    if result.returncode == 0:
                        installed.append({"package": pkg, "status": "installed"})
                    else:
                        failed.append({"package": pkg, "error": result.stderr[:200]})
                except Exception as e:
                    failed.append({"package": pkg, "error": str(e)})

        automation_tools = [
            "automation.soar_playbooks",
            "automation.security_orchestration",
            "appsec.cicd_security",
            "automation.ai_agent_development",
        ]

        findings = []
        for tool_name in automation_tools:
            try:
                result = tool_registry.run(tool_name, task=task, target=target)
                tools_used.append(tool_name)
                # Findings were computed here and then silently discarded
                # (`if result.get("findings"): pass`) — now actually kept.
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                skipped.append({"tool": tool_name, "reason": f"not available: {e}"})

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Installation completed: {len(installed)} installed, {len(skipped)} skipped, {len(failed)} failed",
            metadata={
                "installed": installed,
                "skipped": skipped,
                "failed": failed,
                "tools_used": tools_used,
                "environment_ready": len(failed) == 0,
            },
        )
