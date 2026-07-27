# Architecture

## Overview

NEXUS-STRIKE is built on a modular, layered architecture designed for extensibility, safety, and AI-powered security automation. The system comprises 7 core layers.

```
┌─────────────────────────────────────────────────────────────┐
│                      Interface Layer                          │
│  CLI (nexus run/live/tools/agents/providers) | MCP Server    │
├─────────────────────────────────────────────────────────────┤
│                    Orchestration Layer                        │
│  Mission Planner | Agent Router | Phase Executor | Reporter  │
├─────────────────────────────────────────────────────────────┤
│                       Agent Mesh                             │
│  Offensive │ Defensive │ Analysis │ Orchestrator │ Specialized│
├─────────────────────────────────────────────────────────────┤
│                      Tool Fabric                              │
│  29 domains, 260+ tools (network, webapp, recon, cloud, ...) │
├─────────────────────────────────────────────────────────────┤
│                    Intelligence Layer                         │
│  LLM Router │ 10 Provider Adapters (OpenAI, Anthropic, ...)  │
├─────────────────────────────────────────────────────────────┤
│                      Runtime Layer                            │
│  Tool Executor │ Guardrails │ Schema │ Audit │ Sandbox       │
├─────────────────────────────────────────────────────────────┤
│                      Foundation Layer                         │
│  Config │ Logging │ Pydantic Models │ Environment            │
└─────────────────────────────────────────────────────────────┘
```

## Layer Details

### 1. Foundation Layer
The bedrock of the platform providing configuration management, structured logging, and data models.

- **Config** (`nexus/foundation/config.py`): Pydantic-based settings with `.env` file support, covering LLM providers, execution parameters, guardrails, and infrastructure connections.
- **Logging** (`nexus/foundation/logging.py`): Structured logging to console and rotating files.
- **Schema** (`nexus/foundation/schema.py`): Canonical `Finding` dataclass, status constants, and `tool_result()` result builder used by every tool.

### 2. Runtime Layer
Enforces safety, auditability, and contract compliance.

- **Guardrails** (`nexus/foundation/guardrails/`):
  - **ScopeGuard**: Target allow-list enforcement using hostnames, wildcards, IPs, and CIDR notation
  - **LegalGuard**: Requires written authorization acknowledgement before scanning
  - **RateGuard**: Sliding-window rate limiting per target
  - **InputGuard**: Blocks prompt injection, command injection, and path traversal in inputs
  - **EscalationGuard**: Requires human approval for destructive actions (exploit, RCE, SQLi, etc.)
  - **OutputGuard**: Prevents secret leakage (passwords, API keys, private keys) in tool output
  - **AuditGuard**: Append-only JSON audit log of every tool execution for forensic traceability
- **Tool Executor** (`nexus/tools/executor.py`): Unified execution wrapper that validates tool contracts, normalizes findings, enforces all guardrails, and provides consistent error handling.

### 3. Intelligence Layer
Multi-provider LLM abstraction for AI-powered security analysis.

- **LLM Router** (`nexus/intelligence/llm/router.py`): Auto-selects active provider, provides failover.
- **10 Providers**: OpenAI, Anthropic, OpenRouter, Ollama, Azure, Groq, DeepSeek, Omniroute, NVIDIA NIM, Custom.

### 4. Tool Fabric
All 260+ security tools across 29 domains.

| Domain | Example Tools | Status |
|--------|--------------|--------|
| reconnaissance | dns_recon, subdomain_enum, cert_transparency, whois_lookup | ✅ Real |
| network | port_scan, banner_grab, host_discovery, firewall_detect | ✅ Real |
| webapp | sqli, xss, lfi, cmdi, ssrf, dir_enum | ✅ Real |
| cloud | aws_review, azure_assessment, container_scanning, k8s_security | 📝 Stub |
| active_directory | kerberoast, asrep_roast, bloodhound, pass_the_hash | 📝 Stub |
| malware | pe_analysis, yara_rules, sandbox_execution, behavior_analysis | 📝 Stub |
| ... | 29 domains total | Mixed |

Tools self-register via `tool_registry.register("domain.tool_name", run, metadata={...})`.

### 5. Agent Mesh
Specialized AI agents that orchestrate tools and interpret results.

- **Offensive**: recon_agent, network_agent, webapp_agent, exploit_agent, ad_agent, cloud_agent, mobile_agent, wireless_agent, redteam_agent, social_eng_agent, api_attacker_agent
- **Defensive**: soc_agent, ir_agent, threat_hunt_agent, detection_engineer_agent, blue_team_agent, hardening_agent, deception_agent
- **Analysis**: malware_agent, forensics_agent, reverse_eng_agent, threat_intel_agent, vuln_analyst_agent
- **Orchestrator**: mission_commander_agent, task_planner_agent, agent_router_agent
- **Specialized**: iot_agent, ot_ics_agent, automotive_agent, hardware_agent, ai_security_agent, compliance_auditor_agent
- **Support**: searcher_agent, coder_agent, reporter_agent, validator_agent, debugger_agent, doc_writer_agent

### 6. Orchestration Layer
Mission planning and execution engine.

- **OrchestrationEngine** (`nexus/orchestration/engine.py`): Plans missions using LLM, delegates to agents, collects findings, generates reports.
- **ReportGenerator** (`nexus/reporting/generator.py`): Produces structured reports with executive summaries, findings, and recommendations.

### 7. Interface Layer
Multiple access points for interacting with the platform.

- **CLI** (`nexus/cli.py`): Rich Typer-based command-line interface with 12+ commands
- **MCP Server**: Model Context Protocol server for IDE integration (Claude Desktop, Cursor, etc.)

## Execution Flow

### `nexus live --target X` (Direct Pipeline)

```
CLI → scripts/live_agent.py → Tool Functions → Consolidated Report
```

Fastest path to results. Runs real port scanning, banner grabbing, DNS recon, HTTP fingerprinting, SQLi detection, SSL inspection, and AI-powered analysis. Recommended for active assessments.

### `nexus run --target X` (Orchestrated Pipeline)

```
CLI → OrchestrationEngine → LLM Planner → Agent Delegation → Tool Registry → Findings → Report Generator
```

Plans the mission via LLM, then delegates to agents. Each agent calls tools from the Tool Fabric. Results are collected, analyzed, and compiled into a structured report.

## Guardrail Flow

Every tool execution passes through the Guardrail Pipeline:

```
Input → InputGuard → ScopeGuard → LegalGuard → EscalationGuard → RateGuard → AuditGuard → Tool Run → OutputGuard → Result
```

If any guardrail rejects the execution, the tool is blocked with a descriptive error message.

## Security Considerations

- All guardrails are enforced server-side; they cannot be bypassed from the client
- ScopeGuard requires explicit target allow-listing via `NEXUS_ALLOWED_TARGETS`
- LegalGuard enforces written authorization acknowledgement (`NEXUS_LEGAL_ACK`)
- AuditGuard creates tamper-evident audit trails of all tool executions
- RateGuard prevents accidental DoS on targets
- EscalationGuard blocks destructive actions without human approval