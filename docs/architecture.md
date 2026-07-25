# Architecture

NEXUS-STRIKE is a modular cybersecurity platform with 7 layers.

## Layer 1: Foundation

Core utilities that every component depends on:

- **Config** (`nexus/foundation/config.py`): Environment-based configuration for LLM providers, targets, rate limits, and legal acknowledgement
- **Schema** (`nexus/foundation/schema.py`): Unified `Finding` dataclass and `tool_result()` builder — every tool MUST use this
- **Guardrails** (`nexus/foundation/guardrails/`): Input validation, scope enforcement, legal checks, rate limiting, audit logging, output sanitization
- **Logging** (`nexus/foundation/logging.py`): Structured logging with console and file output
- **Auth** (`nexus/foundation/auth.py`): Access control manager
- **Secrets** (`nexus/foundation/secrets.py`): Secret management interface

## Layer 2: Tool Fabric

264 registered tools across 29 domains. Each tool:

1. Accepts `target: str` and `**kwargs`
2. Returns a `dict` with `status`, `findings`, `summary`, `error`, `metadata`
3. Uses `Finding` dataclass for all findings
4. Returns truthful statuses: `completed`, `no_findings`, `failed`, `unavailable`, `out_of_scope`, `requires_credentials`, `requires_hardware`, `not_implemented`

### Tool Registration

```python
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import Finding, STATUS_COMPLETED, tool_result

def run(target: str, **kwargs) -> dict:
    findings = [Finding(title="Example", severity="info", ...)]
    return tool_result("domain.tool_name", target, findings=findings, status=STATUS_COMPLETED)

tool_registry.register("domain.tool_name", run, metadata={...})
```

### Domain Structure

```
nexus/tools/
├── network/          Port scan, service enum, host discovery, OS fingerprint, banner grab
├── webapp/           SQLi, XSS, SSRF, LFI, RFI, command injection, directory enumeration, SSL test, crawler
├── reconnaissance/   Subdomain enum, DNS recon, tech fingerprint
├── cloud/            AWS review, Azure assessment, GCP review, IAM audit
├── forensics/        Log analysis, timeline, registry, memory, disk, browser
├── appsec/           Secret scanning, SAST, dependency analysis, IaC checks
├── malware/          YARA rules, PE analysis, sandbox, behavior analysis
├── reverse_engineering/  Symbol recovery, binary patching, debugging
├── exploit_dev/      Shellcode, ROP chains, heap exploitation
├── wireless/         WPA, WPS, Bluetooth, NFC, rogue AP
├── mobile/           Android/iOS security
├── hardware/         Firmware, JTAG, UART
├── active_directory/ AD attacks, LDAP, Kerberos, GPO
├── iam/              IAM audit, policy analysis
├── threat_intel/     IOC collection, threat feeds, campaign analysis
├── soc/              SIEM monitoring, alert investigation, SOAR
├── purple_team/      Detection testing, rule improvement
├── ai_security/      LLM prompt injection, model extraction, adversarial ML
└── ... (29 domains total)
```

## Layer 3: Agents

56 agents organized into 6 tiers:

- **Orchestrator**: MissionCommander, TaskPlanner, AgentRouter, PatternSelector, QualityAssessor
- **Offensive**: Recon, Network, WebApp, Exploit, AD, Cloud, Mobile, Wireless, RedTeam, SocialEng, Phishing, APIAttacker
- **Defensive**: SOC, IR, ThreatHunt, DetectionEngineer, BlueTeam, Hardening, Deception
- **Analysis**: Malware, Forensics, ReverseEng, ThreatIntel, Crypto, CodeReview, OSINT, VulnAnalyst, SupplyChain
- **Support**: Searcher, Coder, Installer, Reporter, Validator, Debugger, DocWriter, HITLLiaison
- **Specialized**: IoT, OT/ICS, Automotive, Hardware, RF/SDR, AI Security, Compliance, Embedded

Each agent implements `BaseAgent.run(task, **kwargs) -> dict`.

## Layer 4: Orchestration Engine

The `OrchestrationEngine` coordinates missions:

1. **Validate** — Scope, legal, escalation guardrails
2. **Plan** — LLM decomposes mission into phases
3. **Execute** — Runs domain-specific tools via ToolExecutor
4. **Report** — Generates Markdown report with normalized findings

## Layer 5: Reporting

- **Markdown** — Human-readable reports with executive summary, severity heatmap, asset inventory, findings, remediation priorities
- **JSON** — Machine-parseable findings export
- **CSV** — Spreadsheet-compatible findings
- **HTML** — Styled HTML report
- **SARIF** — Static Analysis Results Interchange Format for CI/CD integration

## Layer 6: Interface

- **CLI** (`nexus` command via Typer) — Full terminal interface
- **MCP** (Model Context Protocol) — IDE integration (placeholder)
- **FastAPI** — REST API service (placeholder for Phase 2)

## Layer 7: LLM Integration

Multi-provider LLM router supporting:
- OpenAI, Anthropic, OpenRouter, Ollama, Azure, Groq, DeepSeek, Omniroute, Custom
- Auto-detection of available providers
- Fallback chain when primary provider fails
- Offline mock mode when no provider configured

## Key Design Principles

1. **Truthful statuses** — Tools never return `completed` after failure without showing limitation
2. **Normalized findings** — Every tool uses the `Finding` dataclass schema
3. **Guardrails first** — No network action without scope/legal/rate-limit validation
4. **Engagement required** — Non-local targets require an engagement record
5. **Evidence-based** — Every finding includes machine-parseable evidence
6. **Cross-platform** — Windows and Linux compatible Python CLI