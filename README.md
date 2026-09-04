# 🏴‍☠️ NEXUS-STRIKE

**Autonomous AI Cybersecurity Agent — Real Pentest, Real Findings, Real CVE Reports**

NEXUS-STRIKE is an open-source multi-agent cybersecurity assessment platform. It performs live port scanning, service fingerprinting, web vulnerability detection (SQLi, XSS, LFI, CMDi, SSRF), and CVE-enriched risk analysis — all orchestrated by a locally-running or cloud LLM.

Supports **100 % free & local LLMs** (via [Ollama](https://ollama.com)) as well as cloud providers (OpenAI, Anthropic, Groq, OpenRouter, NVIDIA NIM, DeepSeek).

> **Legal notice** — NEXUS-STRIKE is intended **only** for legal, authorised security testing and educational research. You must obtain written permission from the system owner before scanning any target you do not own. The developers assume no liability for misuse.

---

## ⚡ Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/harinish45/harrysecurity-agent.git
cd nexus-strike
pip install -e .
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env to set your LLM provider
```

### 3. Run a Live Assessment

```bash
# Scan localhost (safe for testing)
nexus live --target 127.0.0.1

# Scan an authorised target with a specific model
nexus live --target 192.168.1.10 --llm-model qwen2.5-coder:latest

# Full mission-style assessment
nexus run --target example.internal --mode autonomous --objective full_assessment
```

---

## 🤖 LLM Provider Setup

### Option A — Local Ollama (Free & Private, Recommended)

```bash
ollama pull qwen2.5-coder:latest
```

```ini
# .env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen2.5-coder:latest
```

### Option B — Cloud APIs (OpenAI / Anthropic / Groq / OpenRouter)

```ini
# .env — pick one
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# or
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# or
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...
```

### Option C — Custom OpenAI-Compatible Endpoint

```ini
LLM_PROVIDER=custom
CUSTOM_BASE_URL=http://127.0.0.1:20128/v1
CUSTOM_MODEL=auto/best-coding
CUSTOM_API_KEY=sk-your-key
```

---

## 🚀 CLI Reference

```
nexus COMMAND [OPTIONS]

Commands:
  live          Run the live AI agent (port scan + web vuln + AI report)
  run           Launch a full security assessment mission (dependency-batched,
                concurrent FlowController dispatch to real agents)
  agent         Run a single agent directly — `agent run <name> --target <t>`
  advanced      Run an advanced/experimental module directly — attack-path
                prediction, triage, supply-chain scan, patch re-verification,
                evidence notarization/PQ-signing, threat-radar (NVD/CISA KEV),
                genetic-algorithm fuzzing, honeypot, ASM baseline, and more
                (`advanced list` for the full set — 11 real, 4 honest stubs)
  compliance    Generate a control-mapping gap-analysis report — SOC2,
                ISO27001, NIST_CSF, GDPR, HIPAA, PCI_DSS (illustrative, not a
                certification)
  auth          Manage dashboard/API user accounts
  view          Launch the web dashboard
  skills        List/run registered security skills
  engage        Create an authorised-engagement record before scanning
  preflight     Verify host readiness and security controls
  tools         List all registered security tools across 29 domains
  agents        List all registered AI agents (`--tier` to filter)
  providers     Show LLM provider configuration status
  export-report Export findings to a portable report file
  config-show   Show current NEXUS-STRIKE configuration
  verify        Offline integrity check for all bundled tools
  version       Show version information
  mcp           Start the MCP server for IDE integration (Claude Desktop, Cursor)

# Common flags:
nexus live --target <ip>                  # Quick scan
nexus live --target <ip> --ports 80,443,8080  # Custom ports
nexus run  --target <ip> --mode autonomous --objective vuln_scan
nexus run  --target <ip> --engagement ./my_engagement.json
nexus agent run recon_agent --target <ip>
nexus advanced threat-radar openssl --version 3.0.0
nexus compliance report SOC2
nexus preflight --strict
```

---

## 🔐 Authorization & Safety

NEXUS-STRIKE enforces **7 built-in guardrails** on every tool execution:

| Guardrail | What it does |
|-----------|-------------|
| `InputGuard` | Blocks prompt injection, command injection, path traversal |
| `ScopeGuard` | Validates target against `NEXUS_ALLOWED_TARGETS` allow-list |
| `LegalGuard` | Requires `NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION` |
| `EscalationGuard` | Human approval required for destructive actions (RCE, SQLi) |
| `RateGuard` | Sliding-window rate limiting prevents accidental DoS |
| `AuditGuard` | Append-only JSON audit log of every execution |
| `OutputGuard` | Redacts API keys, passwords, and private keys from output |

```bash
# Before scanning any authorised target, create an engagement record:
nexus engage

# Set scope in .env:
NEXUS_ALLOWED_TARGETS=192.168.1.0/24,example.internal
NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION
```

---

## 🧰 Tool Coverage

| Domain | Tools | Examples |
|--------|-------|---------|
| `webapp` | 27 | SQLi, XSS, LFI, SSRF, JWT, IDOR, CSRF |
| `network` | 11 | Port scan, SMB enum, SNMP, banner grab |
| `reconnaissance` | 12 | Subdomain enum, Shodan, OSINT, WHOIS |
| `cloud` | 11 | AWS IAM, S3, Azure, GCP, Kubernetes |
| `malware` | 17 | PE analysis, YARA, sandbox, behavioural |
| `wireless` | 12 | WPA, BLE, Zigbee, evil twin, deauth |
| `active_directory` | 11 | Kerberoast, BloodHound, pass-the-hash |
| … + 22 more | **266 total** | across 29 domains |

```bash
nexus tools            # list all 266 tools
nexus tools --domain webapp   # filter by domain
```

---

## 📄 Report Output

Reports are written to `engagements/<mission-id>/` and include:

- **JSON findings** — structured CVE-enriched results
- **Markdown report** — human-readable pentest narrative
- **Audit log** — append-only execution record

---

## 📚 Documentation

| Doc | Description |
|-----|-------------|
| [docs/quickstart.md](docs/quickstart.md) | First scan in 5 minutes |
| [docs/architecture.md](docs/architecture.md) | Agent mesh & tool fabric design |
| [docs/tool_development.md](docs/tool_development.md) | Write your own tools |
| [docs/extension_guide.md](docs/extension_guide.md) | Custom agents, providers, guardrails |
| [docs/security_considerations.md](docs/security_considerations.md) | Hardening & safe deployment |
| [docs/deployment.md](docs/deployment.md) | Docker, Kubernetes, Terraform |

---

## 📜 License

[MIT License](LICENSE)