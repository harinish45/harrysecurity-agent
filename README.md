# 🏴‍☠️ NEXUS-STRIKE

**The Ultimate AI-Powered Cybersecurity Platform**

An autonomous, multi-agent penetration testing and security operations framework covering **29 security domains**, orchestrated by **54 specialist agents** using **6 agentic patterns**, powered by **9 LLM providers**.

## 🚀 Features

### 29 Security Domains
Reconnaissance | Network | WebApp | Wireless | Active Directory | Cloud | Mobile | Malware Analysis | Reverse Engineering | Exploit Development | Forensics | Incident Response | Threat Intelligence | SOC Operations | Vulnerability Assessment | Red Team | Blue Team | Purple Team | IoT | OT/ICS | Automotive | Hardware | RF/SDR | Cryptography | IAM | Compliance | AppSec | AI Security | Automation

### 9 LLM Providers
| Provider | Type | API Key Required |
|----------|------|------------------|
| **OpenAI** | GPT-4, GPT-3.5 | ✅ `OPENAI_API_KEY` |
| **Anthropic** | Claude 3 Opus/Sonnet/Haiku | ✅ `ANTHROPIC_API_KEY` |
| **OpenRouter** | 200+ models (GPT, Claude, Llama, Mistral) | ✅ `OPENROUTER_API_KEY` |
| **Ollama** | Local LLMs (Llama 3, Mistral, CodeLlama) | ❌ Runs locally |
| **Azure** | Azure OpenAI Service | ✅ `AZURE_OPENAI_API_KEY` |
| **Groq** | Ultra-fast LPU inference | ✅ `GROQ_API_KEY` |
| **DeepSeek** | DeepSeek Chat/Coder | ✅ `DEEPSEEK_API_KEY` |
| **Omniroute** | Multi-provider routing | ✅ `OMNIROUTE_API_KEY` |
| **Custom** | Any OpenAI-compatible endpoint | ✅ `CUSTOM_API_KEY` |

### 54 Specialist Agents
Organized into 6 tiers: **Orchestrator** (5) | **Offensive** (13) | **Defensive** (7) | **Analysis** (9) | **Specialized** (8) | **Support** (8)

### 6 Agentic Patterns
Hierarchical | Swarm | Chain-of-Thought | Auction | Recursive | Hybrid

### 7-Layer Guardrails
Input Guard | Scope Guard | Legal Guard | Output Guard | Escalation Guard | Rate Guard | Audit Guard

### 500+ Security Tools
Every tool auto-registers in the Tool Fabric across all 29 domains.

## 📦 Quick Start

```bash
# Install
pip install -e .

# Configure (choose your LLM provider)
cp .env.example .env
# Edit .env with your API keys

# Run a mission
nexus run --target example.com

# List tools
nexus tools
nexus tools --domain reconnaissance

# List agents
nexus agents
nexus agents --tier offensive

# Check LLM providers
nexus providers

# Show configuration
nexus config
```

## 🎯 Usage Examples

```bash
# Full assessment with specific LLM provider
nexus run --target example.com --mode autonomous --provider openrouter

# Quick OSINT scan
nexus run --target example.com --objective osint --mode tool

# Interactive mode
nexus run --target 10.0.0.1 --mode interactive

# Use local Ollama
nexus run --target test.local --provider ollama

# Filter tools by domain
nexus tools --domain webapp
nexus tools --domain network

# Filter agents by tier
nexus agents --tier offensive
nexus agents --tier defensive
```

## 🏗 Architecture

```
Layer 7: Interface & Delivery      (CLI, API, MCP, Web, SDK)
Layer 6: Orchestration Engine      (Flow Control, Scheduling, Handoff, Decision)
Layer 5: Agent Mesh                (54 Agents, 6 Patterns)
Layer 4: Tool Fabric               (500+ Tools across 29 domains)
Layer 3: Intelligence Core         (9 LLM Providers, Memory, Knowledge, Reasoning)
Layer 2: Execution Runtime         (Sandbox, Process Manager, Connectors)
Layer 1: Foundation                (Config, 7-Layer Guardrails, Logging, Auth)
```

## 🔧 Configuration

Set your preferred LLM provider in `.env`:

```bash
# Active provider
LLM_PROVIDER=openai

# Or switch to local
LLM_PROVIDER=ollama

# Or use OpenRouter for 200+ models
LLM_PROVIDER=openrouter
```

## 📊 Stats

- **584 files** across **107 directories**
- **29 security domains** with specialized tools
- **500+ security tools** auto-registered
- **54 specialized agents** across 6 tiers
- **6 agentic patterns** for orchestration
- **9 LLM providers** for AI intelligence
- **7-layer guardrail system** for safety
- **10 playbooks** for common scenarios
- **8 documentation files**

## ⚖️ Legal

**Use only on systems you own or have explicit written authorization to test.**
This tool is designed for authorized security research, penetration testing, and defensive operations.

The 7-layer guardrail system enforces scope and legal compliance at runtime.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your tools, agents, or providers
4. Submit a pull request

---

Built with ❤️ for the global security community. 🏴‍☠️