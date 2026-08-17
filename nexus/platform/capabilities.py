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


def _add(
    key: str,
    title: str,
    domain: str,
    description: str,
    *,
    existing: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> None:
    catalogue.register(CapabilitySpec(
        key=key,
        title=title,
        domain=domain,
        description=description,
        states=frozenset({CapabilityState.REGISTERED}),
        existing_components=existing,
        tags=tags,
    ))


# Engagement and operating modes.
for key, title in {
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
    "workflow.multi_target": "Multi-Target Engagements",
    "workflow.resume": "Resume Interrupted Engagements",
}.items():
    _add(key, title, "workflow", title, existing=("nexus.mission", "nexus.orchestration"))

for name in [
    "engagement_creation", "engagement_package", "rules_of_engagement", "scope_management",
    "threat_profile", "conops", "deconfliction", "contact_plan", "data_handling",
    "abort_criteria", "cleanup_plan", "opplan", "objective_graph", "allowed_tools",
    "excluded_tools", "allowed_techniques", "excluded_techniques", "credential_inventory",
    "network_boundaries", "destructive_action_policy", "approval_requirements", "time_window",
    "rate_limits", "multiple_simultaneous_engagements", "engagement_persistence",
]:
    _add(f"engagement.{name}", name.replace("_", " ").title(), "engagement", f"Engagement-control capability: {name.replace('_', ' ')}.")


# Planning, intelligence and reasoning.
for domain, names in {
    "planning": [
        "fixed_pipeline", "task_graph", "interactive_task_tree", "adaptive_replanning",
        "objective_prioritization", "attack_chain_construction", "task_create", "task_delete",
        "task_reorder", "task_split", "task_merge", "task_retry", "task_block", "task_skip",
        "task_priority", "next_action_selection", "critical_path_analysis",
    ],
    "intelligence": [
        "knowledge_graph", "asset_graph", "evidence_correlation", "confidence_engine",
        "finding_deduplication", "target_fingerprinting", "attack_path", "cross_finding_chaining",
        "attack_surface_model", "behavioral_corroboration", "false_positive_reduction",
        "objective_context", "hypothesis_tracking",
    ],
    "security": [
        "prompt_injection_defense", "untrusted_output_classification", "provenance_tracking",
        "instruction_data_separation", "attacker_controlled_data_marking",
    ],
}.items():
    for name in names:
        _add(f"{domain}.{name}", name.replace("_", " ").title(), domain, f"Unified {name.replace('_', ' ')} capability.")


# Agent roles described by the unified inventory.
_AGENT_ROLES = [
    "supervisor", "engagement_planner", "task_planner", "refiner", "resource_manager", "policy",
    "researcher", "coder", "executor", "installer", "searcher", "memorist", "adviser", "reflector",
    "enricher", "summarizer", "reporter", "tool_call_fixer", "recon", "exploit", "post_exploit",
    "analyst", "reverse_engineering", "contract_auditor", "cloud_hunter", "active_directory",
    "phisher", "mobile", "wireless", "osint", "iot", "ics", "forensics", "supply_chain",
    "api_security", "web_application", "browser", "source_code_security", "container_security",
    "ai_security", "detection_engineering", "purple_team", "validation", "deception",
    "network", "threat_intelligence", "malware", "crypto", "compliance", "embedded", "hardware", "rf_sdr",
]

_existing_agent_roles = {
    "recon", "network", "web_application", "exploit", "active_directory", "cloud", "mobile",
    "wireless", "osint", "iot", "ics", "forensics", "supply_chain", "ai_security", "deception",
    "api_security", "validation", "coder", "installer", "searcher", "reporter", "malware",
    "reverse_engineering", "crypto", "compliance", "hardware", "rf_sdr",
}
for role in _AGENT_ROLES:
    existing = ("nexus.agents.agent_registry",) if role in _existing_agent_roles else ()
    _add(
        f"agent.{role}",
        role.replace("_", " ").title(),
        "agents",
        f"Unified {role.replace('_', ' ')} agent role.",
        existing=existing,
    )


# Vulnerability research and validation pipeline.
for name in ["scanner", "detector", "verifier", "exploiter", "patcher", "second_technique_validation", "second_scanner_validation", "source_confirmation", "behavioral_confirmation", "environment_reproduction"]:
    _add(f"validation.{name}", name.replace("_", " ").title(), "validation", f"Validation stage: {name.replace('_', ' ')}.")


# Tool fabric and tool categories.
for domain, names in {
    "tools.network": ["nmap", "naabu", "masscan", "dns", "service_enum", "host_discovery", "network_map"],
    "tools.web": ["nuclei", "katana", "http_probe", "crawler", "dast", "proxy"],
    "tools.vulnerability": ["cve", "osv", "epss", "sqlmap", "nuclei_templates"],
    "tools.exploitation": ["metasploit", "controlled_exploit_runner", "exploit_validation"],
    "tools.active_directory": ["bloodhound", "directory_enum", "identity_graph"],
    "tools.reverse": ["ghidra", "radare2", "binary_analysis"],
    "tools.mobile": ["apk_analysis", "jadx", "apktool", "dynamic_instrumentation", "mobsf"],
    "tools.cloud": ["cloud_cli", "kubernetes", "iam_analysis", "iac_review", "container_analysis"],
    "tools.osint": ["search", "dns", "certificate_intelligence", "public_datasets", "code_leak_intelligence"],
    "tools.source": ["semgrep", "bandit", "secret_scanning", "dependency_scanning", "dataflow"],
    "tools.ai_security": ["garak", "prompt_injection_harness", "agent_security_harness", "model_evaluation"],
    "tools.browser": ["isolated_browser", "dom_extraction", "screenshots", "network_inspection", "workflow_replay"],
}.items():
    for name in names:
        _add(f"{domain}.{name}", name.replace("_", " ").title(), domain, f"Tool category capability: {name.replace('_', ' ')}.")

for name in [
    "tool_registry", "tool_profile", "tool_adapter", "input_schema", "output_schema", "evidence_schema",
    "finding_schema", "tool_dependencies", "resource_requirements", "credential_requirements",
    "timeout_policy", "concurrency_policy", "rate_limit_policy", "fallback_tools", "workflow_compatibility",
    "foreground_execution", "background_execution", "persistent_sessions", "interactive_prompt_detection",
    "command_lifecycle", "output_normalization", "execution_telemetry",
]:
    _add(f"execution.{name}", name.replace("_", " ").title(), "execution", f"Execution-fabric capability: {name.replace('_', ' ')}.")


# Workers and isolation.
for domain, names in {
    "sandbox": ["docker_sandbox", "network_isolation", "management_network_separation", "restricted_egress", "scoped_workspace", "credential_isolation", "disposable_workers", "read_only_filesystem", "capability_drop", "resource_limits"],
    "workers": ["local_worker", "remote_worker", "gpu_worker", "high_isolation_worker", "browser_worker", "specialist_worker", "worker_pool", "distributed_execution"],
}.items():
    for name in names:
        _add(f"{domain}.{name}", name.replace("_", " ").title(), domain, f"Runtime capability: {name.replace('_', ' ')}.")


# Memory and context fabric.
for name in [
    "working_memory", "episodic_memory", "semantic_memory", "procedural_memory", "engagement_memory",
    "long_term_memory", "vector_memory", "graph_memory", "context_compaction", "rolling_summaries",
    "objective_context", "fresh_specialist_context", "parent_child_context", "relevant_memory_retrieval",
    "evidence_filtering", "irrelevant_output_suppression", "session_persistence",
]:
    _add(f"memory.{name}", name.replace("_", " ").title(), "memory", f"Memory/context capability: {name.replace('_', ' ')}.")


# LLM and provider fabric.
for name in [
    "provider_registry", "model_registry", "provider_test", "connectivity_test", "authentication_test",
    "generation_test", "tool_calling_test", "structured_output_test", "streaming_test", "reasoning_test",
    "vision_test", "latency_test", "model_routing", "fallback_chain", "local_ai", "ollama", "vllm",
    "llamacpp", "lmstudio", "openai_compatible", "embedding_providers", "prompt_registry", "prompt_versioning",
    "agent_model_assignment", "model_health", "llm_observability", "cost_budgeting", "token_accounting",
]:
    _add(f"llm.{name}", name.replace("_", " ").title(), "llm", f"LLM-fabric capability: {name.replace('_', ' ')}.")


# Search, browser and skill/plugin systems.
for domain, names in {
    "search": ["search_aggregation", "duckduckgo", "google", "tavily", "perplexity", "searxng", "security_search", "vulnerability_search", "documentation_search"],
    "browser": ["navigate", "click", "type", "wait", "inspect_dom", "inspect_network", "capture_screenshot", "download", "session_cookies", "replay", "form_discovery", "endpoint_discovery", "request_correlation"],
    "platform": ["skill_registry", "skill_metadata", "skill_prerequisites", "plugin_registry", "agent_plugins", "tool_plugins", "middleware_plugins", "provider_plugins", "workflow_plugins", "report_plugins", "dashboard_widgets"],
}.items():
    for name in names:
        _add(f"{domain}.{name}", name.replace("_", " ").title(), domain, f"Platform capability: {name.replace('_', ' ')}.")


# Governance, evidence and findings.
for domain, names in {
    "governance": ["scope_guard", "authorization_guard", "risk_policy", "approval_gate", "egress_policy", "credential_boundary", "audit_logging", "rollback", "circuit_breaker"],
    "evidence": ["immutable_provenance", "artifact_integrity", "terminal_output", "http_response", "screenshot", "source_file", "binary", "log", "json", "pcap", "scan_output", "model_observation"],
    "findings": ["finding_schema", "deduplication", "fingerprints", "severity", "confidence", "asset", "location", "reproduction", "root_cause", "attack_path", "impact", "cwe", "cve", "cvss", "epss", "mitre", "remediation", "validation_status", "related_findings"],
}.items():
    for name in names:
        _add(f"{domain}.{name}", name.replace("_", " ").upper(), domain, f"Unified {domain} capability: {name.replace('_', ' ')}.")


# Reporting, defense, ATT&CK, CI/CD and research/benchmarking.
for domain, names in {
    "reporting": ["executive", "technical", "developer", "red_team", "purple_team", "machine_readable", "html", "pdf", "markdown", "sarif", "csv"],
    "defense": ["detection_engineering", "sigma", "yara", "suricata", "snort", "siem_queries", "edr_logic", "report_to_defense", "attack_observe_detect_patch_retest"],
    "attack": ["mitre_attack", "technique_mapping", "objective_mapping", "finding_mapping", "action_mapping", "detection_mapping", "attack_path_reasoning"],
    "deception": ["honeypot_manager", "decoy_deployment", "adaptive_decoy_responses", "attacker_telemetry", "ai_attacker_detection", "offensive_vaccine_loop"],
    "cicd": ["pull_request_security_gate", "source_analysis", "build_test_environment", "agent_assessment", "security_gate", "pass_fail_policy"],
    "research": ["experiment_builder", "benchmark_runner", "dataset_management", "model_comparison", "agent_comparison", "tool_comparison", "prompt_comparison", "trace_export", "reproducibility", "success_rate", "latency_metrics", "cost_metrics", "regression_benchmark"],
}.items():
    for name in names:
        _add(f"{domain}.{name}", name.replace("_", " ").title(), domain, f"Unified {domain} capability: {name.replace('_', ' ')}.")


# API, authentication and enterprise.
for name in [
    "rest", "graphql", "websocket", "sse", "local_auth", "oauth", "api_tokens", "rbac", "project_isolation",
    "organization", "project", "engagement_tenant", "admin_role", "security_lead_role", "operator_role",
    "analyst_role", "viewer_role", "service_role", "multi_tenancy", "audit_scope",
]:
    _add(f"enterprise.{name}", name.replace("_", " ").title(), "enterprise", f"Enterprise/API capability: {name.replace('_', ' ')}.")


# Bounded self-improvement.
for name in [
    "execution_observation", "baseline_learning", "performance_recommendation", "failure_pattern_detection",
    "evidence_yield_analysis", "regression_evaluation", "canary_evaluation", "approval_gated_improvement",
    "versioned_rollout", "rollback_improvement",
]:
    _add(f"learning.{name}", name.replace("_", " ").title(), "learning", f"Bounded self-improvement capability: {name.replace('_', ' ')}.")


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
