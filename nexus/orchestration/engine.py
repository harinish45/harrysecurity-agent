"""
NEXUS-STRIKE Orchestration Engine
Core mission execution engine with LLM-powered planning, agent delegation, and state management.
"""
from rich.console import Console

from nexus.agents.base_agent import AgentContext
from nexus.agents.orchestrator.pattern_selector_agent import PatternSelectorAgent
from nexus.agents.orchestrator.quality_assessor_agent import QualityAssessorAgent
from nexus.foundation.guardrails import LegalGuard, ScopeGuard, EscalationGuard
from nexus.intelligence.llm.router import LLMRouter
from nexus.foundation.logging import logger
from nexus.orchestration.flow.flow_controller import FlowController
from nexus.reporting.generator import ReportGenerator

console = Console()

class OrchestrationEngine:
    """Central orchestration engine that plans and executes security missions."""

    def __init__(self, llm_provider: str = None):
        self.llm = LLMRouter(provider=llm_provider)
        self.mission_context = None

    async def run_mission(self, target: str, mission_id: str = "mission-001",
                          mode: str = "guided", objective: str = "full_assessment",
                          engagement: dict | None = None) -> dict:
        """Execute a complete security assessment mission."""
        console.print(f"[bold green]OrchestrationEngine: Starting mission {mission_id} on {target}[/]")
        logger.info(f"Mission {mission_id} started: target={target}, mode={mode}")

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

        # Phase 3: Plan mission using LLM, informed by the orchestrator tier's
        # pattern_selector_agent (which of the coordination patterns in
        # nexus.agents.patterns best fits this objective/mode).
        pattern_suggestion = await self._select_pattern(objective, mode, target)
        plan = await self._plan_mission(target, mode, objective)
        self.mission_context.add_to_history(
            f"Mission planned: {len(plan)} phase(s), suggested pattern={pattern_suggestion.get('pattern')}"
        )

        # Phase 4: Execute the plan — dependency-batched and concurrency-bounded,
        # each phase dispatched to its real nexus.agents.* class (not just
        # tool-grabbed by domain).
        controller = FlowController(mission_id)
        results = await controller.run(plan)
        for phase_result in results:
            for f in phase_result.get("findings") or []:
                self.mission_context.add_finding(f)
        self.mission_context.add_to_history(
            f"Mission executed via FlowController: strategy={controller.strategy}"
        )

        # Phase 4.5: Quality-assess the collected findings before reporting.
        quality_assessment = await self._assess_quality(target, self.mission_context.findings)

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
            "pattern_suggestion": pattern_suggestion,
            "execution_strategy": controller.strategy,
            "quality_assessment": quality_assessment,
            "report": report,
            "report_path": report_path,
            "llm_provider": self.llm.get_provider_info(),
            "status": "completed",
        }

    async def _select_pattern(self, objective: str, mode: str, target: str) -> dict:
        """Ask pattern_selector_agent which coordination pattern best fits
        this mission — informational (shown in the result/history), doesn't
        override FlowController's own dependency-driven concurrency choice."""
        try:
            result = await PatternSelectorAgent().run(f"{objective} ({mode})", target=target)
            metadata = result.get("metadata", {})
            return {"pattern": metadata.get("pattern", "chain_of_thought"), "reasoning": metadata.get("reasoning", "")}
        except Exception as e:
            logger.warning(f"pattern_selector_agent failed: {e}")
            return {"pattern": "chain_of_thought", "reasoning": "fallback: pattern selection failed"}

    async def _assess_quality(self, target: str, findings: list) -> dict:
        """Ask quality_assessor_agent to risk-score the mission's collected
        findings before they go into the report."""
        if not findings:
            return {"overall_risk_score": 0.0, "validated_findings": []}
        try:
            result = await QualityAssessorAgent().run("Assess mission findings", target=target, findings=findings)
            metadata = result.get("metadata", {})
            return {
                "overall_risk_score": metadata.get("overall_risk_score", 0.0),
                "validated_findings": metadata.get("validated_findings", []),
                "severity_counts": metadata.get("severity_counts", {}),
            }
        except Exception as e:
            logger.warning(f"quality_assessor_agent failed: {e}")
            return {"overall_risk_score": 0.0, "validated_findings": [], "error": str(e)}

    async def _plan_mission(self, target: str, mode: str, objective: str) -> list:
        """Use LLM to decompose the mission into phases."""
        prompt = f"""You are a penetration testing mission planner. Plan a security assessment for target: {target}
Mode: {mode}
Objective: {objective}

Available domains: reconnaissance, network, webapp, wireless, active_directory, cloud, mobile, malware,
reverse_engineering, exploit_dev, forensics, incident_response, threat_intel, iam, compliance, appsec, ai_security

Return a JSON list of phases with agent and task for each phase. Phases that
can safely run at the same time (no phase depends on another's output) may
say so explicitly with a "depends_on" list of the earlier phase ids;
otherwise phases are assumed to run in the order given.
Format: [{{"id": "P1", "agent": "recon_agent", "task": "description", "domain": "reconnaissance", "depends_on": []}}]
"""

        response = self.llm.complete(prompt, system="You are a cybersecurity mission planner. Return only valid JSON.")
        logger.debug(f"LLM plan response: {response[:200]}...")

        import json as json_mod
        plan = None
        try:
            parsed = json_mod.loads(response)
            if isinstance(parsed, list) and len(parsed) > 0:
                plan = parsed
        except (json_mod.JSONDecodeError, TypeError):
            pass

        if plan is None:
            # Default plan if LLM fails — recon first, then network and webapp
            # assessment run concurrently (neither depends on the other),
            # vuln analysis waits on both, then reporting.
            plan = [
                {"id": "P1", "agent": "recon_agent", "task": f"Reconnaissance on {target}", "domain": "reconnaissance", "depends_on": []},
                {"id": "P2", "agent": "network_agent", "task": f"Network scan on {target}", "domain": "network", "depends_on": ["P1"]},
                {"id": "P3", "agent": "webapp_agent", "task": f"Web application assessment on {target}", "domain": "webapp", "depends_on": ["P1"]},
                {"id": "P4", "agent": "vuln_analyst_agent", "task": f"Vulnerability analysis on {target}", "domain": "vuln_assessment", "depends_on": ["P2", "P3"]},
                {"id": "P5", "agent": "reporter_agent", "task": f"Generate report for {target}", "domain": "automation", "depends_on": ["P4"]},
            ]

        # Fill in anything the LLM omitted: an id, a conservative sequential
        # dependency on the previous phase (so unlabelled LLM output keeps the
        # old strictly-sequential behaviour rather than guessing it's safe to
        # parallelize), and the mission target.
        for i, phase in enumerate(plan):
            phase.setdefault("id", f"P{i + 1}")
            if "depends_on" not in phase:
                phase["depends_on"] = [plan[i - 1]["id"]] if i > 0 else []
            phase.setdefault("target", target)

        return plan

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
