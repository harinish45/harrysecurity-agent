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

## 💸 Running NEXUS-STRIKE for $0

Every LLM-dependent feature (mission planning, all orchestrator agents, the benchmark
harness, report-tone rendering) works end-to-end on providers that cost nothing to run.
Check what's actually configured and its real cost at any time with:

```bash
nexus providers
```

which prints a live table (Provider / Status / Model / Configured / **Cost**) and warns
you if your active provider has no free tier. Real classification, verified against each
provider's published pricing (checked 2026-09) — not marketing copy:

| Provider | Cost | Why |
|---|---|---|
| **Ollama** | 🟢 Free | Runs 100% locally, no API key, no request limit — the only truly unlimited option |
| **Groq** | 🟢 Free tier | No credit card required; 30 req/min, 14,400 req/day, all models included |
| **OpenRouter** | 🟢 Free tier | 28+ models with an `:free` suffix at $0/token; ~20 req/min, no card needed |
| **NVIDIA NIM** | 🟢 Free tier | build.nvidia.com hosted catalog, free developer credits, 50+ open models |
| **Omniroute** | 🟢 Free tier | Free token/dashboard quota (OpenAI-compatible relay) |
| **DeepSeek** | 🟡 Very low cost | Not free, but among the cheapest paid options if you outgrow the free tiers |
| **OpenAI** | 🔴 Paid only | No free tier |
| **Anthropic Claude** | 🔴 Paid only | No free tier |
| **Azure OpenAI** | 🔴 Paid only | No free tier |
| **Custom** | ❓ Depends | Whatever you point it at (e.g. LM Studio/Antigravity running locally = free) |

**Recommended $0 setup**: `LLM_PROVIDER=ollama` (fully local, zero network dependency) with
`LLM_PROVIDER=groq` as your cloud fallback when you need faster inference than your local
hardware gives you — both are pre-wired with sane defaults in `.env.example`.

**Beyond the LLM**: a handful of individual recon tools optionally use paid third-party
data APIs for deeper results (Shodan's full Search API, Censys). Those are opt-in — the
platform doesn't require them:
- `reconnaissance.shodan_search` uses Shodan's free, unauthenticated **InternetDB**
  endpoint by default (no key needed, real open-port/CVE data) and only calls the paid
  Search API if you explicitly set `SHODAN_API_KEY`.
- `reconnaissance.cert_transparency` and `reconnaissance.github_recon` use crt.sh and the
  GitHub public search API — both free, no key required.
- `reconnaissance.censys_search` (needs a free-to-create Censys account's `CENSYS_PAT`
  token — the account itself is free, API usage beyond it may not be) and `ai_security`
  tools that need a live model endpoint or a licensed dataset honestly report what's
  missing (`requires_credentials` / `requires_file`) instead of guessing.

---

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

### Option B1 — Free-Tier Cloud APIs (Groq / OpenRouter / NVIDIA NIM / Omniroute)

```ini
# .env — pick one, all $0 to start
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...          # https://console.groq.com — no card required

# or
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-...  # https://openrouter.ai — use a *:free model
OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free

# or
LLM_PROVIDER=nvidia
NVIDIA_API_KEY=nvapi-...      # https://build.nvidia.com — free developer credits
```

### Option B2 — Paid Cloud APIs (OpenAI / Anthropic / Azure)

```ini
# .env — no free tier on any of these
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# or
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
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
  tools         List all registered security tools across 30 domains
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

### Mode commands

Thin wrappers over `run()` that restrict which tool domains the LLM planner can choose from and pick a mode-appropriate report template (see `nexus/foundation/agent_profiles.py`):

```
nexus pentest  --target <scope> [--engagement <path>] [--mission <id>] [--provider <name>]
               # 🔒 Authorized penetration-test engagement — full guardrails, formal audit report

nexus bounty   --target <scope> [--program <H1/Bugcrowd id>] [--engagement <path>] [--mission <id>] [--provider <name>]
               # 💰 Bug-bounty engagement — web/API/cloud/mobile-focused, platform-style submission report
               # --program is not wired to a live bounty-platform API in this build; scope-pull is a stub

nexus ctf      --target <host/URL> [--category pwn|web|crypto|rev|forensics|misc] [--mission <id>] [--provider <name>]
               # 🚩 CTF challenge solving — category-scoped tools, writeup-style report

nexus redteam  --target <scope> [--objective <TTP chain>] [--engagement <path>] [--mission <id>] [--provider <name>]
               # 🎯 Adversary emulation — MITRE ATT&CK-mapped TTP chain, redteam-format report

nexus blueteam --target <scope> [--mission <id>] [--provider <name>]
               # 🛡️ Defensive assessment — detection engineering and incident triage, incident-format report

nexus benchmark [--suite intercode_ctf|cybench|nyu_ctf|debate_consensus_eval] [--latency [--agent <name>]] [--provider <name>]
               # 📊 Score the agent stack against Cybench/NYU-CTF/InterCode-CTF-style suites (bundled smoke
               # suite ships out of the box; full licensed datasets are not bundled), evaluate
               # debate_consensus_agent's precision/recall, or benchmark per-agent execution latency
```

---

## 🔐 Authorization & Safety

Every tool call routes through a single guarded entrypoint (`ToolExecutor`) that applies **9 built-in guardrails**, in order, before and after execution:

| Guardrail | What it does |
|-----------|-------------|
| `InputGuard` | Multi-layer: length/entropy, control characters, prompt/command/path-traversal injection regexes, Unicode NFKC normalization + zero-width/bidi-override stripping, homoglyph collapse |
| `ScopeGuard` | Validates target (hostname, wildcard, CIDR) against `NEXUS_ALLOWED_TARGETS`; resolves hostnames and requires every resolved address to be in scope |
| `LegalGuard` | Requires `NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION` |
| `EscalationGuard` | Human approval required for destructive actions (RCE, SQLi, credential dumping, wipers, etc.), matched against separator-normalized tool/action names |
| `RateGuard` | Thread-safe, per-target sliding-window rate limiting |
| `AuditGuard` | Append-only, SHA-256 hash-chained audit log — any single-entry tamper (edit, delete, reorder) breaks the chain and is detectable via `verify_chain()` |
| `InjectionGuard` | Scans target-originated content (tool output, evidence) for prompt-injection patterns before it reaches any LLM prompt; supports canary-token integrity checks |
| `BudgetGuard` | Per-mission LLM spend/token tracking with a configurable hard-stop threshold |
| `OutputGuard` | Redacts API keys, passwords, and private keys from tool output — findings that legitimately discovered a real secret on the target are redacted (evidence sanitized, `[REDACTED]` marker) rather than dropped entirely, so the finding itself still reaches the report |

Two additional cross-cutting defenses, applied centrally rather than per-tool:

- **SSRF / redirect / DNS-rebinding protection** (`safe_urlopen()`, `nexus/foundation/net.py`) — every one of the ~280 tools that make outbound HTTP requests goes through this single choke point. Every redirect hop is re-validated against the same scope check the original target had to pass (capped at 5 hops), so a target can't SSRF-pivot a tool to an internal address or cloud-metadata endpoint (`169.254.169.254`) via a `Location:` header.
- **Execution sandboxing** (`nexus/tools/sandbox.py`) — subprocess-spawning tools (binary/firmware analysis, fuzzing) get real wall-clock timeouts plus CPU/memory limits: kernel-enforced `RLIMIT_CPU`/`RLIMIT_AS` on POSIX, a `psutil`-based watchdog on Windows.

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
| … + 22 more | **283 total** | across 30 domains |

```bash
nexus tools            # list all 283 tools
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