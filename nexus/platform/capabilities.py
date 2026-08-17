"""Unified capability taxonomy and parity metadata.

This module is intentionally declarative. It turns the large feature inventory
into machine-readable platform capabilities without implying that every
external tool is installed or that every capability is production-ready.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import FrozenSet


class CapabilityState(StrEnum):
    REGISTERED = "registered"
    CALLABLE = "callable"
    CONTRACT_VALID = "contract_valid"
    EXECUTABLE = "executable"
    EVIDENCE_VALID = "evidence_valid"
    RESULT_VALID = "result_valid"
    RELIABLE = "reliable"
    PRODUCTION_READY = "production_ready"


class WorkflowMode(StrEnum):
    AUTONOMOUS = "autonomous"
    GUIDED = "guided"
    INTERACTIVE = "interactive"
    CTF = "ctf"
    PENTEST = "pentest"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    RESEARCH = "research"
    VULNERABILITY_RESEARCH = "vulnerability_research"
    AI_SECURITY = "ai_security"
    SCHEDULED = "scheduled"


@dataclass(frozen=True)
class CapabilitySpec:
    key: str
    title: str
    domain: str
    description: str
    states: FrozenSet[CapabilityState] = frozenset()
    prerequisites: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    existing_components: tuple[str, ...] = ()


@dataclass
class CapabilityCatalogue:
    specs: dict[str, CapabilitySpec] = field(default_factory=dict)

    def register(self, spec: CapabilitySpec) -> None:
        self.specs[spec.key] = spec

    def get(self, key: str) -> CapabilitySpec | None:
        return self.specs.get(key)

    def by_domain(self, domain: str) -> list[CapabilitySpec]:
        return sorted(
            (item for item in self.specs.values() if item.domain == domain),
            key=lambda item: item.key,
        )

    def coverage(self) -> dict[str, int]:
        return {
            "total": len(self.specs),
            "production_ready": sum(
                CapabilityState.PRODUCTION_READY in item.states
                for item in self.specs.values()
            ),
            "registered": sum(
                CapabilityState.REGISTERED in item.states
                for item in self.specs.values()
            ),
        }


catalogue = CapabilityCatalogue()


def _add(
    key: str,
    title: str,
    domain: str,
    description: str,
    *,
    existing: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> None:
    catalogue.register(
        CapabilitySpec(
            key=key,
            title=title,
            domain=domain,
            description=description,
            states=frozenset({CapabilityState.REGISTERED}),
            existing_components=existing,
            tags=tags,
        )
    )


for key, title, description in [
    ("workflow.autonomous_assessment", "Autonomous Assessment", "Run a bounded autonomous assessment lifecycle."),
    ("workflow.human_in_loop", "Human-in-the-Loop", "Require explicit human control or approvals."),
    ("workflow.ctf", "CTF Mode", "Challenge-oriented workflow with reproducible walkthrough state."),
    ("workflow.pentest", "Pentest Mode", "Structured authorized penetration-test workflow."),
    ("workflow.red_team", "Red Team Mode", "Rules-of-engagement-driven adversary simulation workflow."),
    ("workflow.purple_team", "Purple Team Mode", "Attack, detection, improvement and retest loop."),
    ("workflow.research", "Research Mode", "Reproducible experiments and agent/tool benchmarking."),
    ("workflow.vulnerability_research", "Vulnerability Research", "Candidate to validation to evidence to remediation pipeline."),
    ("workflow.ai_security", "AI Security Testing", "Assessment workflow for LLM and agent security."),
    ("workflow.scheduled", "Scheduled Assessments", "Repeatable, resumable assessment schedules."),
]:
    _add(
        key,
        title,
        "workflow",
        description,
        existing=("nexus.mission", "nexus.orchestration"),
    )


for key, title, domain in [
    ("intelligence.task_graph", "Dynamic Task Graph", "planning"),
    ("intelligence.interactive_task_tree", "Interactive Task Tree", "planning"),
    ("intelligence.attack_path", "Attack-Path Analysis", "planning"),
    ("intelligence.knowledge_graph", "Security Knowledge Graph", "intelligence"),
    ("intelligence.evidence_correlation", "Evidence Correlation", "intelligence"),
    ("intelligence.confidence_engine", "Finding Confidence Engine", "intelligence"),
    ("intelligence.finding_deduplication", "Finding Deduplication", "intelligence"),
    ("intelligence.target_fingerprinting", "Target Intelligence", "reconnaissance"),
    ("intelligence.context_compaction", "Context Compaction", "llm"),
    ("intelligence.prompt_injection_defense", "Prompt Injection Defense", "security"),
    ("intelligence.adaptive_replanning", "Adaptive Replanning", "planning"),
]:
    _add(key, title, domain, f"Unified {title.lower()} capability.")


for key, title, domain in [
    ("agent.supervisor", "Supervisor", "orchestration"),
    ("agent.engagement_planner", "Engagement Planner", "orchestration"),
    ("agent.task_planner", "Task Planner", "orchestration"),
    ("agent.refiner", "Refiner", "orchestration"),
    ("agent.resource_manager", "Resource Manager", "orchestration"),
    ("agent.policy", "Policy Agent", "governance"),
    ("agent.researcher", "Researcher", "support"),
    ("agent.coder", "Developer/Coder", "support"),
    ("agent.executor", "Executor", "support"),
    ("agent.installer", "Installer", "support"),
    ("agent.searcher", "Searcher", "support"),
    ("agent.memorist", "Memorist", "memory"),
    ("agent.adviser", "Adviser", "support"),
    ("agent.reflector", "Reflector", "quality"),
    ("agent.enricher", "Enricher", "analysis"),
    ("agent.summarizer", "Summarizer", "support"),
    ("agent.reporter", "Reporter", "reporting"),
    ("agent.tool_call_fixer", "Tool-Call Fixer", "support"),
    ("agent.api_security", "API Security Agent", "webapi"),
    ("agent.web_application", "Web Application Agent", "webapp"),
    ("agent.browser", "Browser Agent", "browser"),
    ("agent.source_code_security", "Source Code Security Agent", "appsec"),
    ("agent.container_security", "Container Security Agent", "cloud"),
    ("agent.ai_security", "AI Security Agent", "ai_security"),
    ("agent.detection_engineering", "Detection Engineering Agent", "defensive"),
    ("agent.purple_team", "Purple Team Agent", "defensive"),
    ("agent.validation", "Validation Agent", "quality"),
    ("agent.recon", "Recon Agent", "reconnaissance"),
    ("agent.cloud", "Cloud Hunter", "cloud"),
    ("agent.active_directory", "AD Operator", "active_directory"),
    ("agent.mobile", "Mobile Operator", "mobile"),
    ("agent.wireless", "Wireless Operator", "wireless"),
    ("agent.osint", "OSINT Operator", "reconnaissance"),
    ("agent.iot", "IoT Operator", "iot"),
    ("agent.ics", "ICS Operator", "ot_ics"),
    ("agent.reverse_engineering", "Reverse Engineering Agent", "reverse_engineering"),
    ("agent.forensics", "Forensics Agent", "forensics"),
    ("agent.supply_chain", "Supply Chain Agent", "supply_chain"),
    ("agent.deception", "Deception Agent", "deception"),
]:
    _add(key, title, domain, f"Unified {title} role exposed through the agent fabric.")


for key, title, domain in [
    ("evidence.immutable_provenance", "Immutable Evidence Provenance", "evidence"),
    ("evidence.artifact_integrity", "Artifact Integrity", "evidence"),
    ("report.executive", "Executive Report", "reporting"),
    ("report.technical", "Technical Report", "reporting"),
    ("report.developer", "Developer Report", "reporting"),
    ("report.red_team", "Red Team Report", "reporting"),
    ("report.purple_team", "Purple Team Report", "reporting"),
    ("report.machine_readable", "Machine-Readable Reports", "reporting"),
    ("defense.detection_bridge", "Report-to-Defense Bridge", "defensive"),
    ("defense.honeypot_management", "Honeypot Management", "deception"),
    ("defense.ai_attacker_detection", "AI Attacker Detection", "deception"),
    ("platform.skill_registry", "Dynamic Skill Registry", "platform"),
    ("platform.plugin_registry", "Plugin Registry", "platform"),
    ("platform.middleware", "Composable Middleware", "platform"),
    ("platform.observability", "Multi-Layer Observability", "platform"),
    ("platform.audit_log", "Tamper-Evident Audit Log", "platform"),
    ("platform.multi_engagement", "Multiple Simultaneous Engagements", "platform"),
    ("platform.resume", "Resumable Engagements", "platform"),
    ("platform.multitenancy", "Multi-Tenant Isolation", "enterprise"),
    ("platform.rbac", "Role-Based Access Control", "enterprise"),
    ("platform.api", "Unified REST/GraphQL API", "api"),
    ("platform.websocket_stream", "Realtime Event Streaming", "api"),
]:
    _add(key, title, domain, f"Unified {title} capability.")


def feature_parity_matrix() -> list[dict[str, object]]:
    """Return a stable machine-readable parity matrix for UI/reporting/tests."""
    coverage = catalogue.coverage()
    return [
        {
            "key": spec.key,
            "title": spec.title,
            "domain": spec.domain,
            "state": sorted(state.value for state in spec.states),
            "implemented": bool(spec.existing_components),
            "existing_components": list(spec.existing_components),
            "tags": list(spec.tags),
            "coverage_total": coverage["total"],
            "coverage_production_ready": coverage["production_ready"],
        }
        for spec in sorted(catalogue.specs.values(), key=lambda item: item.key)
    ]
