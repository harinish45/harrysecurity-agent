"""
NEXUS-STRIKE Orchestration Engine
Core mission execution engine with LLM-powered planning, agent delegation, and state management.
"""
from rich.console import Console
import json as json_mod
import asyncio
from concurrent.futures import ThreadPoolExecutor
from nexus.agents.base_agent import AgentContext
from nexus.foundation.guardrails import LegalGuard, ScopeGuard, EscalationGuard
from nexus.intelligence.llm.router import LLMRouter
from nexus.foundation.logging import logger
from nexus.tools.registry import tool_registry
from nexus.tools.executor import ToolExecutor
from nexus.reporting.generator import ReportGenerator

console = Console()

class OrchestrationEngine:
    """Central orchestration engine that plans and executes security missions."""

    def __init__(self, llm_provider: str = None):
        self.llm = LLMRouter(provider=llm_provider)
        self.mission_context = None
        self.tool_executor = ToolExecutor()

    async def run_mission(self, target: str, mission_id: str = "mission-001",
                          mode: str = "guided", objective: str = "full_assessment",
                          engagement: dict | None = None, hat_mode: str = "white",
                          workflow: str = "full_assessment") -> dict:
        """Execute a complete security assessment mission."""
        console.print(f"[bold green]OrchestrationEngine: Starting mission {mission_id} on {target}[/]")
        logger.info(f"Mission {mission_id} started: target={target}, mode={mode}, hat_mode={hat_mode}, workflow={workflow}")

        # Phase 1: Validate
        try:
            ScopeGuard.validate(target)
            LegalGuard.validate(target=target)
            EscalationGuard.validate(f"mission_{mission_id}", "execute")
        except Exception as e:
            logger.error(f"Guardrail validation failed: {e}")
            return {"mission_id": mission_id, "status": "blocked", "error": str(e)}

        # Phase 2: Create context
        self.mission_context = AgentContext(mission_id=mission_id, target=target)

        # Phase 3: Plan mission using LLM
        plan = await self._plan_mission(target, mode, objective, hat_mode, workflow)
        self.mission_context.add_to_history(f"Mission planned: {len(plan)} phases")

        # Phase 4: Execute phases
        results = []
        for phase in plan:
            phase_result = await self._execute_phase(phase)
            results.append(phase_result)
            if phase_result.get("findings"):
                for f in phase_result["findings"]:
                    self.mission_context.add_finding(f)

        # Phase 5: Generate report
        report, report_path = await self._generate_report(self.mission_context.findings, engagement)

        return {
            "mission_id": mission_id,
            "target": target,
            "mode": mode,
            "objective": objective,
            "plan": plan,
            "results": results,
            "findings": self.mission_context.findings,
            "report": report,
            "report_path": report_path,
            "llm_provider": self.llm.get_provider_info(),
            "status": "completed",
        }

    async def _plan_mission(self, target: str, mode: str, objective: str, hat_mode: str = "white", workflow: str = "full_assessment") -> list:
        """Use LLM to decompose the mission into phases."""
        prompt = f"""You are a penetration testing mission planner. Plan a security assessment for target: {target}
Mode: {mode}
Objective: {objective}
Hat Mode: {hat_mode} (white=authorized, grey=ambiguous, black=unauthorized simulation)
Workflow: {workflow}

Available domains: reconnaissance, network, webapp, wireless, active_directory, cloud, mobile, malware,
reverse_engineering, exploit_dev, forensics, incident_response, threat_intel, iam, compliance, appsec, ai_security,
container, api, physical, ai_ml, blockchain

Return a JSON list of phases with agent and task for each phase.
Format: [{{"agent": "recon_agent", "task": "description", "domain": "reconnaissance"}}]
"""

        response = self.llm.complete(prompt, system="You are a cybersecurity mission planner. Return only valid JSON.")
        logger.debug(f"LLM plan response: {response[:200]}...")

        import json as json_mod
        try:
            plan = json_mod.loads(response)
            if isinstance(plan, list) and len(plan) > 0:
                return plan
        except (json_mod.JSONDecodeError, TypeError):
            pass

        # Default plan if LLM fails
        return [
            {"agent": "recon_agent", "task": f"Reconnaissance on {target}", "domain": "reconnaissance"},
            {"agent": "network_agent", "task": f"Network scan on {target}", "domain": "network"},
            {"agent": "webapp_agent", "task": f"Web application assessment on {target}", "domain": "webapp"},
            {"agent": "vuln_analyst_agent", "task": f"Vulnerability analysis on {target}", "domain": "vuln_assessment"},
            {"agent": "reporter_agent", "task": f"Generate report for {target}", "domain": "automation"},
        ]

    async def _execute_phase(self, phase: dict) -> dict:
        """Execute a single mission phase using the appropriate agent with parallel tool execution."""
        agent_name = phase.get("agent", "recon_agent")
        task = phase.get("task", "Unknown task")
        domain = phase.get("domain", "reconnaissance")

        console.print(f"[cyan]Executing phase: {agent_name} -> {task[:60]}...[/]")
        logger.info(f"Phase: {agent_name} | Task: {task}")

        # Execute relevant tools for the domain
        findings = []
        domain_tools = tool_registry.list_by_domain(domain)

        # Run up to 5 tools from the domain in parallel using ThreadPoolExecutor
        tools_to_run = domain_tools[:5]
        
        def run_tool(tool_name):
            try:
                result = self.tool_executor.run(
                    tool_name,
                    target=self.mission_context.target if self.mission_context else "",
                )
                return result
            except Exception as e:
                logger.warning(f"Tool {tool_name} failed: {e}")
                return {"findings": []}

        if tools_to_run:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=5) as executor:
                # Run all tools in parallel threads
                results = await asyncio.gather(
                    *(loop.run_in_executor(executor, run_tool, tool_name) for tool_name in tools_to_run)
                )
            for result in results:
                if result and result.get("findings"):
                    findings.extend(result["findings"])

        return {
            "agent": agent_name,
            "task": task,
            "domain": domain,
            "findings": findings,
            "status": "completed",
        }

    async def _generate_report(self, findings: list, engagement: dict | None = None) -> tuple[str, str]:
        """Generate a deterministic report and retain it as assessment evidence."""
        from pathlib import Path
        import re

        generator = ReportGenerator()
        mission_id = self.mission_context.mission_id if self.mission_context else "assessment"
        target = self.mission_context.target if self.mission_context else ""
        report = generator.generate(findings, target=target, mission_id=mission_id, engagement=engagement)
        safe_mission = re.sub(r"[^A-Za-z0-9_.-]+", "-", mission_id).strip(".-") or "assessment"
        report_path = generator.write(report, Path("reports") / f"{safe_mission}.md")
        return report, str(report_path)

    def get_mission_status(self) -> dict:
        """Get current mission status."""
        if not self.mission_context:
            return {"status": "idle"}
        return {
            "mission_id": self.mission_context.mission_id,
            "target": self.mission_context.target,
            "findings_count": len(self.mission_context.findings),
            "history_count": len(self.mission_context.history),
            "llm_provider": self.llm.get_provider_info(),
        }
