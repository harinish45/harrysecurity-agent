<div align="center">

# 🛡️ NEXUS-STRIKE

**AI-Powered Autonomous Cybersecurity Platform**

[![CI](https://github.com/harinish45/harrysecurity-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/harinish45/harrysecurity-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Security](https://img.shields.io/badge/Security-Trivy%20Scanned-critical)](https://trivy.dev)

> *Autonomous security platform combining LLM intelligence with real-world penetration testing workflows*

[📋 TODO](TODO.md) · [🔒 Security Policy](SECURITY.md) · [🤝 Contributing](CONTRIBUTING.md)

</div>

---

## 🏗️ Platform Architecture

```mermaid
graph TB
    subgraph Input["🎯 Engagement Input"]
        Scope["Target Scope\n(IPs, Domains, Apps)"]
        Creds["Credentials\n(API Keys, Tokens)"]
    end

    subgraph Nexus["⚡ NEXUS Core Orchestrator"]
        Planner["🧠 AI Planner\n(LLM)"]
        Router["🔀 Task Router"]
        Memory["📦 Knowledge Store"]
    end

    subgraph Agents["🤖 Security Agents"]
        Recon["🔍 Recon Agent\n(OSINT + Nmap)"]
        Vuln["🎯 Vuln Scanner\n(CVE Lookup)"]
        LogAI["📊 Log Analyst\n(Anomaly ML)"]
        ThreatIntel["🌐 Threat Intel\n(VirusTotal, Shodan)"]
    end

    subgraph Output["📤 Outputs"]
        Report["📄 Security Report\n(PDF/Markdown)"]
        Dashboard["📊 Web Dashboard"]
        Alerts["🚨 Alerts\n(Slack/Email)"]
    end

    Scope --> Planner
    Creds --> Memory
    Planner --> Router
    Router --> Recon
    Router --> Vuln
    Router --> LogAI
    Router --> ThreatIntel
    Recon --> Memory
    Vuln --> Memory
    LogAI --> Memory
    ThreatIntel --> Memory
    Memory --> Report
    Memory --> Dashboard
    Memory --> Alerts
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/harinish45/harrysecurity-agent.git
cd harrysecurity-agent

# With Docker (recommended)
docker compose up --build

# Local
pip install -r requirements.txt
make dev
```

---

## 📋 Feature Coverage

| Module | Status | Priority |
|--------|--------|----------|
| 🔍 OSINT / Recon Agent | 🔧 In Progress | HIGH |
| 🎯 Vulnerability Scanner | 🔧 In Progress | HIGH |
| 📊 Log Analysis (ML) | 📋 Planned | HIGH |
| 🌐 Threat Intelligence | 📋 Planned | MEDIUM |
| 📄 Report Generator | 📋 Planned | MEDIUM |
| 🌐 Web Dashboard | 🔧 In Progress | MEDIUM |
| 🔒 Compliance Mapping | 📋 Planned | LOW |

---

## 📁 Structure

```
harrysecurity-agent/
├── 🧠  nexus/           # Core agent orchestration
├── 🌐  web/             # FastAPI web UI
├── 📚  knowledge/       # Threat intelligence KB
├── 💬  prompts/         # LLM prompt library
├── 🎯  engagements/     # Security workflows
├── 🧪  tests/           # Test suite
├── 📊  benchmarks/      # Performance benchmarks
├── 🐳  Dockerfile       # Container
└── 📋  Makefile         # Build commands
```

---

<div align="center">
⚠️ For authorized security testing only · <a href="LICENSE">MIT License</a>
</div>