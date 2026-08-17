"""Unified machine-readable capability and feature-parity catalogue."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CapabilityState(str, Enum):
    REGISTERED = "registered"
    CALLABLE = "callable"
    CONTRACT_VALID = "contract_valid"
    EXECUTABLE = "executable"
    EVIDENCE_VALID = "evidence_valid"
    RESULT_VALID = "result_valid"
    RELIABLE = "reliable"
    PRODUCTION_READY = "production_ready"


class WorkflowMode(str, Enum):
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
    states: frozenset[CapabilityState] = frozenset()
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
        return sorted((x for x in self.specs.values() if x.domain == domain), key=lambda x: x.key)

    def coverage(self) -> dict[str, int]:
        return {
            "total": len(self.specs),
            "registered": sum(CapabilityState.REGISTERED in x.states for x in self.specs.values()),
            "production_ready": sum(CapabilityState.PRODUCTION_READY in x.states for x in self.specs.values()),
        }


catalogue = CapabilityCatalogue()


def _add(key: str, title: str, domain: str, description: str, *, existing: tuple[str, ...] = ()) -> None:
    catalogue.register(CapabilitySpec(
        key=key,
        title=title,
        domain=domain,
        description=description,
        states=frozenset({CapabilityState.REGISTERED}),
        existing_components=existing,
    ))


_WORKFLOWS = {
    "workflow.autonomous_assessment": "Autonomous Assessment",
    "workflow.human_in_loop": "Human-in-the-Loop",
    "workflow.ctf": "CTF Mode",
    "workflow.pentest": "Pentest Mode",
    "workflow.red_team": "Red Team Mode",
    "workflow.purple_team": "Purple Team Mode",
    "workflow.research": "Research Mode",
    "workflow.vulnerability_research": "Vulnerability Research",
    "workflow.ai_security": "AI Security Testing",
    "workflow.scheduled": "Scheduled Assessments",
}
for key, title in _WORKFLOWS.items():
    _add(key, title, "workflow", title, existing=("nexus.mission", "nexus.orchestration"))


_DOMAINS = {
    "planning": ["task_graph", "interactive_task_tree", "attack_path", "adaptive_replanning"],
    "intelligence": ["knowledge_graph", "evidence_correlation", "confidence_engine", "finding_deduplication"],
    "security": ["prompt_injection_defense"],
    "llm": ["context_compaction", "model_routing", "provider_health", "prompt_management"],
    "evidence": ["immutable_provenance", "artifact_integrity"],
    "reporting": ["executive_report", "technical_report", "developer_report", "red_team_report", "purple_team_report", "machine_readable"],
    "defensive": ["detection_engineering", "purple_team", "detection_bridge"],
    "deception": ["honeypot_management", "ai_attacker_detection"],
    "platform": ["skill_registry", "plugin_registry", "middleware", "observability", "audit_log", "multi_engagement", "resume"],
    "enterprise": ["rbac", "multitenancy", "api", "websocket_stream"],
}
for domain, names in _DOMAINS.items():
    for name in names:
        _add(f"{domain}.{name}", name.replace("_", " ").title(), domain, f"Unified {name.replace('_', ' ')} capability.")


_AGENT_ROLES = [
    "supervisor", "engagement_planner", "task_planner", "refiner", "resource_manager", "policy",
    "researcher", "coder", "executor", "installer", "searcher", "memorist", "adviser", "reflector",
    "enricher", "summarizer", "reporter", "tool_call_fixer", "api_security", "web_application", "browser",
    "source_code_security", "container_security", "ai_security", "detection_engineering", "purple_team",
    "validation", "recon", "cloud", "active_directory", "mobile", "wireless", "osint", "iot", "ics",
    "reverse_engineering", "forensics", "supply_chain", "deception",
]
for role in _AGENT_ROLES:
    _add(f"agent.{role}", role.replace("_", " ").title(), "agents", f"Unified {role.replace('_', ' ')} agent role.")


def feature_parity_matrix() -> list[dict[str, object]]:
    coverage = catalogue.coverage()
    return [
        {
            "key": item.key,
            "title": item.title,
            "domain": item.domain,
            "state": sorted(x.value for x in item.states),
            "implemented": bool(item.existing_components),
            "existing_components": list(item.existing_components),
            "tags": list(item.tags),
            "coverage_total": coverage["total"],
            "coverage_production_ready": coverage["production_ready"],
        }
        for item in sorted(catalogue.specs.values(), key=lambda x: x.key)
    ]
