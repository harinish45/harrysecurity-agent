"""
NEXUS-STRIKE Orchestration Engine
Core mission execution engine with LLM-powered planning, agent delegation, and state management.
"""
from rich.console import Console
import json as json_mod
import asyncio
from concurrent.futures import ThreadPoolExecutor
from nexus.agents.base_agent import AgentContext
from nexus.agents.orchestrator.attack_chain_agent import AttackChainAgent
from nexus.agents.orchestrator.blast_radius_agent import BlastRadiusAgent
from nexus.agents.orchestrator.debate_consensus_agent import DebateConsensusAgent
from nexus.agents.orchestrator.mitre_mapping_agent import MitreMappingAgent
from nexus.agents.orchestrator.pattern_selector_agent import PatternSelectorAgent
from nexus.agents.orchestrator.poc_recorder_agent import PocRecorderAgent
from nexus.agents.orchestrator.quality_assessor_agent import QualityAssessorAgent
from nexus.agents.orchestrator.report_tone_agent import ReportToneAgent
from nexus.agents.orchestrator.verification_agent import VerificationAgent
from nexus.agents.support.hitl_liaison_agent import HitlLiaisonAgent
from nexus.foundation.guardrails import LegalGuard, ScopeGuard, EscalationGuard
from nexus.foundation.guardrails.budget_guard import BudgetGuard, BudgetExceededError
from nexus.intelligence.llm.router import LLMRouter
from nexus.foundation.logging import logger
from nexus.orchestration.decision.attack_chain import AttackChain
from nexus.orchestration.flow.flow_controller import FlowController
from nexus.orchestration.recovery.checkpoint import Checkpoint
from nexus.reporting.generator import ReportGenerator
from nexus.foundation.schema import normalize_findings
from nexus.tools.registry import tool_registry

console = Console()

class OrchestrationEngine:
    """Central orchestration engine that plans and executes security missions."""

    def __init__(self, llm_provider: str | None = None, *, emit_events: bool = False):
        self.llm = LLMRouter(provider=llm_provider)
        self.mission_context: AgentContext | None = None
        # When True, print one `NEXUS-EVENT:{json}` line per FlowController
        # batch-start/agent-done to plain stdout (deliberately not through
        # `console`/rich, so the line stays raw-parseable JSON). This is what
        # lets `web/server.py`'s scan subprocess reader turn a CLI-launched
        # mission into structured live WebSocket events instead of only raw
        # text lines — see `_stream_output` there.
        self.emit_events = emit_events

    async def run_mission(self, target: str, mission_id: str = "mission-001",
                          mode: str = "guided", objective: str = "full_assessment",
                          engagement: dict | None = None, allowed_domains: list[str] | None = None,
                          resume: bool = False, hat_mode: str = "white",
                          workflow: str = "full_assessment") -> dict:
        """Execute a complete security assessment mission.

        `resume=True` skips planning (and its LLM call) entirely when a
        checkpoint already exists for `mission_id` — FlowController picks
        the original plan back up from `Checkpoint.load()` instead. Nothing
        happens differently when no checkpoint exists (a resume request for
        a mission that never got a checkpoint just runs fresh, matching
        `Checkpoint.load`'s existing "no file -> None" degrade-safely
        contract).

        `hat_mode`/`workflow` (white/grey/black engagement framing, and a
        workflow label) are accepted for `nexus/cli.py`'s `--hat-mode`
        option and threaded into `_plan_mission`'s prompt context — they
        don't change the real execution path below, which is driven by
        `allowed_domains`/FlowController regardless of hat_mode."""
        console.print(f"[bold green]OrchestrationEngine: Starting mission {mission_id} on {target}[/]")
        logger.info(
            f"Mission {mission_id} started: target={target}, mode={mode}, resume={resume}, "
            f"hat_mode={hat_mode}, workflow={workflow}"
        )

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
        # `self.mission_context` is `AgentContext | None` so it can be
        # inspected before a mission runs (see `get_status` below), but every
        # access from here to the end of this method is on the object just
        # assigned above. mypy can't narrow an instance attribute across the
        # `await` calls in between (any of them could, in principle,
        # reassign it), so carry the guaranteed-non-None reference in a
        # local instead of re-reading `self.mission_context` — a real fix
        # for the 11 "None has no attribute" errors, not a type: ignore.
        mission_context = self.mission_context

        # Phase 3: Plan mission using LLM, informed by the orchestrator tier's
        # pattern_selector_agent (which of the coordination patterns in
        # nexus.agents.patterns best fits this objective/mode) — unless
        # resuming an in-progress mission, in which case the original plan
        # already lives in its checkpoint and re-planning would both waste
        # an LLM call and risk producing a different plan than the one whose
        # partial results we're about to reuse.
        resumable_checkpoint = Checkpoint().load(mission_id) if resume else None
        if resumable_checkpoint and resumable_checkpoint.get("tasks"):
            plan = resumable_checkpoint["tasks"]
            pattern_suggestion = {"pattern": "resumed", "reasoning": "resumed from checkpoint; planning skipped"}
            mission_context.add_to_history(
                f"Mission resumed from checkpoint: batch {resumable_checkpoint.get('batch')}/"
                f"{resumable_checkpoint.get('total_batches')} already completed"
            )
        else:
            pattern_suggestion = await self._select_pattern(objective, mode, target)
            plan = await self._plan_mission(
                target, mode, objective, mission_id, allowed_domains,
                hat_mode=hat_mode, workflow=workflow,
            )
            mission_context.add_to_history(
                f"Mission planned: {len(plan)} phase(s), suggested pattern={pattern_suggestion.get('pattern')}"
            )

        # Phase 4: Execute the plan — dependency-batched and concurrency-bounded,
        # each phase dispatched to its real nexus.agents.* class (not just
        # tool-grabbed by domain). _plan_mission already validates the plan
        # against DependencyGraph before returning it, but this is still
        # wrapped (matching every other stage's fault-tolerance below) in
        # case of an unrelated FlowController-level failure (e.g. checkpoint
        # I/O) — a mission should degrade to "no findings from this stage",
        # never crash outright.
        controller = FlowController(mission_id, on_event=self._emit_event if self.emit_events else None)
        try:
            results = await controller.run(plan, resume=resume)
        except Exception as e:
            logger.error(f"FlowController failed to execute mission plan: {e}")
            results = []
        for phase_result in results:
            for f in phase_result.get("findings") or []:
                mission_context.add_finding(f)
        mission_context.add_to_history(
            f"Mission executed via FlowController: strategy={controller.strategy}"
        )

        # Phase 4.5: post-process the raw findings before they're scored/reported.
        # Older agents (e.g. recon_agent's fallback path) still append plain
        # strings to findings rather than the canonical Finding dict; every
        # stage below assumes dicts, so normalize once here rather than
        # each stage guarding against str entries independently. Each stage
        # is additive and independently fault-tolerant — a stage failing
        # never aborts the mission, matching _select_pattern/_assess_quality's
        # existing resilience style below.
        mission_context.findings = normalize_findings(mission_context.findings)
        chains = await self._find_attack_chains(target, mission_context.findings)
        mission_context.findings.extend(chains)

        mission_context.findings = await self._annotate(
            BlastRadiusAgent(), "blast-radius", target, mission_context.findings,
            metadata_key="annotated_findings", engagement=engagement,
        )
        mission_context.findings = await self._annotate(
            MitreMappingAgent(), "MITRE ATT&CK mapping", target, mission_context.findings,
            metadata_key="annotated_findings",
        )

        quality_assessment = await self._assess_quality(target, mission_context.findings)
        debate_summary = await self._debate_ambiguous(target, quality_assessment.get("validated_findings", []))
        hitl_summary = await self._escalate_to_hitl(target, mission_id, debate_summary.get("escalated", []))
        next_step_recommendation = self._recommend_next_domains(mission_context.findings)

        mission_context.findings = await self._annotate(
            VerificationAgent(), "verification", target, mission_context.findings,
            metadata_key="verified_findings",
        )
        verification_counts = self._count_by_key(mission_context.findings, "verification_status")

        poc_summary = await self._record_poc(target, mission_id, mission_context.findings)
        tone_report = await self._render_tone_report(target, mode, mission_context.findings)
        budget_report = BudgetGuard.report(mission_id)
        if self.emit_events:
            # Mission-mode dashboard launches run in a separate subprocess
            # (see web/server.py's scan_start) with their own in-memory
            # BudgetGuard — the dashboard server process can never see it
            # directly, so GET /api/budget was always 0 for a running
            # mission. Piggyback the snapshot on the same NEXUS-EVENT
            # channel FlowController already uses; the dashboard's
            # _stream_output captures "budget_update" events into
            # _active_scan so /api/budget can serve real numbers.
            self._emit_event({"type": "budget_update", **budget_report})

        # Phase 5: Generate the canonical Markdown report (unchanged path —
        # the new finding keys above are additive, existing exporters keep
        # working whether or not they choose to display them).
        report, report_path = await self._generate_report(mission_context.findings, engagement)

        return {
            "mission_id": mission_id,
            "target": target,
            "mode": mode,
            "objective": objective,
            "plan": plan,
            "results": results,
            "findings": mission_context.findings,
            "attack_chains": chains,
            "pattern_suggestion": pattern_suggestion,
            "execution_strategy": controller.strategy,
            "quality_assessment": quality_assessment,
            "debate_summary": debate_summary,
            "hitl_summary": hitl_summary,
            "next_step_recommendation": next_step_recommendation,
            "verification_summary": verification_counts,
            "poc_summary": poc_summary,
            "tone_report": tone_report,
            "budget_report": budget_report,
            "report": report,
            "report_path": report_path,
            "llm_provider": self.llm.get_provider_info(),
            "status": "completed",
        }

    @staticmethod
    def _emit_event(event: dict) -> None:
        import json as json_mod
        print(f"NEXUS-EVENT:{json_mod.dumps(event, default=str)}", flush=True)

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

    async def _find_attack_chains(self, target: str, findings: list) -> list:
        """Ask attack_chain_agent to graph-search the mission's findings for
        cross-asset chains, returned as extra synthetic findings to append
        (never replaces the originals)."""
        if len(findings) < 2:
            return []
        try:
            result = await AttackChainAgent().run("Find attack chains", target=target, findings=findings)
            return result.get("metadata", {}).get("chains", [])
        except Exception as e:
            logger.warning(f"attack_chain_agent failed: {e}")
            return []

    async def _annotate(self, agent, label: str, target: str, findings: list,
                        *, metadata_key: str, **extra_kwargs) -> list:
        """Run an annotation-style agent (blast_radius/mitre_mapping/
        verification — anything that returns an enriched copy of the
        findings list under `metadata[metadata_key]`) and fall back to the
        unmodified findings if it fails, so one annotation stage failing
        never loses the mission's findings."""
        if not findings:
            return findings
        try:
            result = await agent.run(f"Annotate findings ({label})", target=target, findings=findings, **extra_kwargs)
            annotated = result.get("metadata", {}).get(metadata_key)
            return annotated if annotated else findings
        except Exception as e:
            logger.warning(f"{label} annotation failed: {e}")
            return findings

    async def _debate_ambiguous(self, target: str, review_findings: list) -> dict:
        """Ask debate_consensus_agent to resolve (or escalate) findings
        quality_assessor_agent marked 'review' rather than 'validated'."""
        under_review = [f for f in review_findings if f.get("validation_status") == "review"]
        if not under_review:
            return {"resolved": [], "escalated": []}
        on_round = (lambda round_evt: self._emit_event({"type": "debate_round", **round_evt})) if self.emit_events else None
        try:
            result = await DebateConsensusAgent().run("Debate ambiguous findings", target=target,
                                                       findings=under_review, on_round=on_round)
            metadata = result.get("metadata", {})
            return {"resolved": metadata.get("resolved", []), "escalated": metadata.get("escalated", [])}
        except Exception as e:
            logger.warning(f"debate_consensus_agent failed: {e}")
            return {"resolved": [], "escalated": []}

    async def _escalate_to_hitl(self, target: str, mission_id: str, escalated_findings: list) -> dict:
        """`debate_consensus_agent` labels disagreement-verdict findings
        `escalate_to: "hitl_liaison_agent"`, but nothing ever actually
        called that agent — the label was aspirational. Wire it for real:
        build a review queue via HitlLiaisonAgent and persist it where an
        operator can actually find and act on it, matching
        `poc_recorder_agent`'s `engagements/<mission_id>/` persistence
        pattern."""
        if not escalated_findings:
            return {"review_items": 0, "path": None}
        try:
            result = await HitlLiaisonAgent().run(
                "Queue disputed findings for human review", target=target, findings=escalated_findings,
            )
            metadata = result.get("metadata", {})
            review_items = metadata.get("review_items", [])
            if not review_items:
                return {"review_items": 0, "path": None}

            import json
            import re
            from pathlib import Path

            safe_mission = re.sub(r"[^A-Za-z0-9_.-]+", "-", mission_id).strip(".-") or "mission"
            out_dir = Path("engagements") / safe_mission
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / "hitl_review.json"
            out_path.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
            return {"review_items": len(review_items), "path": str(out_path)}
        except Exception as e:
            logger.warning(f"hitl_liaison_agent escalation failed: {e}")
            return {"review_items": 0, "path": None, "error": str(e)}

    @staticmethod
    def _recommend_next_domains(findings: list) -> list[str]:
        """`AttackChain.recommend_next` (decision-layer PageRank-based
        "what to investigate next" model) was built but never called from
        the live mission pipeline — wire it as informational guidance for
        a follow-up mission, the same non-steering role `pattern_suggestion`
        already plays (it doesn't override FlowController's own choices,
        it's shown in the result for a human/next-mission to act on)."""
        try:
            return AttackChain.recommend_next(findings)
        except Exception as e:
            logger.warning(f"AttackChain.recommend_next failed: {e}")
            return []

    async def _record_poc(self, target: str, mission_id: str, findings: list) -> dict:
        """Ask poc_recorder_agent to persist replayable transcripts for
        every finding verification_agent stamped 'verified'."""
        try:
            result = await PocRecorderAgent().run("Record PoC transcripts", target=target,
                                                    mission_id=mission_id, findings=findings)
            return {"summary": result.get("summary", ""), "poc_files": result.get("metadata", {}).get("poc_files", [])}
        except Exception as e:
            logger.warning(f"poc_recorder_agent failed: {e}")
            return {"summary": "", "poc_files": []}

    async def _render_tone_report(self, target: str, mode: str, findings: list) -> str:
        """Ask report_tone_agent to render the mode-appropriate report body
        (audit/redteam/compliance/bounty/CTF/...) alongside the canonical
        Markdown report generated by ReportGenerator."""
        try:
            result = await ReportToneAgent().run("Render mode report", target=target, mode=mode, findings=findings)
            return result.get("metadata", {}).get("rendered_report", "")
        except Exception as e:
            logger.warning(f"report_tone_agent failed: {e}")
            return ""

    @staticmethod
    def _count_by_key(findings: list, key: str) -> dict:
        counts: dict[str, int] = {}
        for f in findings:
            value = f.get(key)
            if value:
                counts[value] = counts.get(value, 0) + 1
        return counts

    async def _plan_mission(self, target: str, mode: str, objective: str, mission_id: str = "mission",
                            allowed_domains: list[str] | None = None, *,
                            hat_mode: str = "white", workflow: str = "full_assessment") -> list:
        """Use LLM to decompose the mission into phases."""
        domains = ", ".join(allowed_domains) if allowed_domains else (
            "reconnaissance, network, webapp, wireless, active_directory, cloud, mobile, malware, "
            "reverse_engineering, exploit_dev, forensics, incident_response, threat_intel, iam, "
            "compliance, appsec, ai_security, container, api, physical, ai_ml, blockchain"
        )
        prompt = f"""You are a penetration testing mission planner. Plan a security assessment for target: {target}
Mode: {mode}
Objective: {objective}
Hat Mode: {hat_mode} (white=authorized, grey=ambiguous, black=unauthorized simulation)
Workflow: {workflow}

Available domains: {domains}

Return a JSON list of phases with agent and task for each phase. Phases that
can safely run at the same time (no phase depends on another's output) may
say so explicitly with a "depends_on" list of the earlier phase ids;
otherwise phases are assumed to run in the order given.
Format: [{{"id": "P1", "agent": "recon_agent", "task": "description", "domain": "reconnaissance", "depends_on": []}}]
"""

        response = self.llm.complete(prompt, system="You are a cybersecurity mission planner. Return only valid JSON.")
        logger.debug(f"LLM plan response: {response[:200]}...")
        try:
            BudgetGuard.record(mission_id, prompt, response, label="mission_planning")
        except BudgetExceededError as e:
            logger.error(f"Mission planning exceeded configured budget: {e}")
        if self.emit_events:
            self._emit_event({"type": "budget_update", **BudgetGuard.report(mission_id)})

        import json as json_mod
        plan = None
        try:
            parsed = json_mod.loads(response)
            if isinstance(parsed, list) and len(parsed) > 0:
                plan = parsed
        except (json_mod.JSONDecodeError, TypeError):
            pass

        if plan is None:
            plan = self._default_plan(target)

        # Fill in anything the LLM omitted: an id, a conservative sequential
        # dependency on the previous phase (so unlabelled LLM output keeps the
        # old strictly-sequential behaviour rather than guessing it's safe to
        # parallelize), and the mission target.
        for i, phase in enumerate(plan):
            phase.setdefault("id", f"P{i + 1}")
            if "depends_on" not in phase:
                phase["depends_on"] = [plan[i - 1]["id"]] if i > 0 else []
            phase.setdefault("target", target)

        # An LLM-produced plan can hallucinate: a depends_on referencing an
        # id that doesn't exist, a genuine dependency cycle, or two phases
        # sharing the same id (which TaskManager's `{t["id"]: t for t in
        # plan}` would then silently collapse into one, dropping a phase
        # with no error at all). Previously nothing validated this before it
        # reached FlowController/DependencyGraph, so a bad plan crashed the
        # entire mission with an uncaught GraphError instead of degrading —
        # every other stage in this method is independently fault-tolerant;
        # planning should be too. Fall back to the known-safe default plan
        # rather than trying to auto-repair an ambiguous/hallucinated one.
        validation_error = self._validate_plan(plan)
        if validation_error:
            logger.warning(f"LLM-generated plan failed validation ({validation_error}); using default plan instead")
            plan = self._default_plan(target)
            for i, phase in enumerate(plan):
                phase.setdefault("target", target)

        return plan

    @staticmethod
    def _default_plan(target: str) -> list:
        # Recon first, then network and webapp assessment run concurrently
        # (neither depends on the other), vuln analysis waits on both, then
        # reporting.
        return [
            {"id": "P1", "agent": "recon_agent", "task": f"Reconnaissance on {target}", "domain": "reconnaissance", "depends_on": []},
            {"id": "P2", "agent": "network_agent", "task": f"Network scan on {target}", "domain": "network", "depends_on": ["P1"]},
            {"id": "P3", "agent": "webapp_agent", "task": f"Web application assessment on {target}", "domain": "webapp", "depends_on": ["P1"]},
            {"id": "P4", "agent": "vuln_analyst_agent", "task": f"Vulnerability analysis on {target}", "domain": "vuln_assessment", "depends_on": ["P2", "P3"]},
            {"id": "P5", "agent": "reporter_agent", "task": f"Generate report for {target}", "domain": "automation", "depends_on": ["P4"]},
        ]

    @staticmethod
    def _validate_plan(plan: list) -> str | None:
        """Return an error string if `plan` isn't safe to hand to
        DependencyGraph, else None."""
        from nexus.orchestration.scheduler.dependency_graph import DependencyGraph, GraphError

        ids = [phase.get("id") for phase in plan]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            return f"duplicate phase id(s): {sorted(duplicates)}"

        graph = DependencyGraph()
        for phase in plan:
            graph.add_task(phase["id"], phase.get("depends_on") or [])
        try:
            graph.batches()
        except GraphError as e:
            return str(e)
        return None

    async def _execute_phase(self, phase: dict) -> dict:
        """Execute a single mission phase by running up to 5 of its domain's
        registered tools directly, in parallel.

        Not on the real mission path — `run_mission` above dispatches phases
        via `FlowController.run()`, which delegates to real `nexus.agents.*`
        classes (dependency-graph-ordered, guardrail-enforced per tool call
        through `ToolExecutor`) rather than this flat per-domain tool sweep.
        Kept as a real, working, independently-callable alternative/legacy
        execution path — a simpler one-shot "run whatever this domain has"
        primitive that doesn't need a full mission/plan around it."""
        agent_name = phase.get("agent", "recon_agent")
        task = phase.get("task", "Unknown task")
        domain = phase.get("domain", "reconnaissance")

        findings = []
        domain_tools = tool_registry.list_by_domain(domain)

        # Run up to 5 tools from the domain in parallel using ThreadPoolExecutor
        tools_to_run = domain_tools[:5]

        def run_tool(tool_name):
            try:
                return tool_registry.run(
                    tool_name,
                    target=self.mission_context.target if self.mission_context else "",
                )
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
