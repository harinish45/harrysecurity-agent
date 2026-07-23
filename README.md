# 🏴‍☠️ NEXUS-STRIKE

**Autonomous AI Cybersecurity Agent Framework & Real-Time Security Testing**

NEXUS-STRIKE is an open-source, multi-agent AI cybersecurity assessment framework designed to perform automated security reconnaissance, port scanning, service mapping, banner grabbing, and LLM-assisted risk analysis.

Supports **100% free & local LLMs** (via [Ollama](https://ollama.com) or [OmniRoute](https://github.com/diegosouzapw/OmniRoute)) as well as cloud providers (NVIDIA NIM, OpenRouter, Groq, OpenAI, Anthropic).

---

## ⚡ Quick Start (Cloning & Setup)

### 1. Clone the Repository
```bash
git clone https://github.com/harinish45/harrysecurity-agent.git
cd harrysecurity-agent
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
# OR editable install
pip install -e .
```

### 3. Configure Environment
```bash
cp .env.example .env
```
Edit `.env` to select your preferred LLM provider.

---

## 🤖 LLM Provider Setup Options

### Option A: Local Ollama (100% Free & Private)
1. Install [Ollama](https://ollama.com) and pull a coding model:
   ```bash
   ollama pull qwen2.5-coder:latest
   ```
2. Set in `.env`:
   ```ini
   LLM_PROVIDER=ollama
   OLLAMA_BASE_URL=http://localhost:11434/v1
   OLLAMA_MODEL=qwen2.5-coder:latest
   ```

### Option B: OmniRoute Gateway (Auto-routing Free Models)
1. Set up [OmniRoute](https://github.com/diegosouzapw/OmniRoute) on port `20128`.
2. Generate an API key in OmniRoute dashboard (`http://127.0.0.1:20128`).
3. Set in `.env`:
   ```ini
   LLM_PROVIDER=custom
   CUSTOM_BASE_URL=http://127.0.0.1:20128/v1
   CUSTOM_MODEL=auto/best-coding
   CUSTOM_API_KEY=sk-your-omniroute-key
   ```

### Option C: Free Cloud APIs (OpenRouter / NVIDIA / Groq)
Set your API key in `.env` and set `LLM_PROVIDER` accordingly (e.g. `LLM_PROVIDER=openrouter`).

---

## 🚀 Running the Agent

### 1. Run Live Security Assessment Script
Execute a real-time security assessment on localhost/authorized targets:
```bash
python scripts/live_agent.py
```

What it does:
- ⚡ Multi-threaded TCP Port Scanning
- 🏷️ Service Mapping & Banner Grabbing
- 🌐 Reverse DNS & HTTP Fingerprinting
- 🔐 SSL/TLS Inspection
- 🤖 AI Risk Analysis & Automated Pentest Report Generation

### 2. Test Available Free LLM Providers
Test latency and availability of your configured LLM backends:
```bash
python scripts/test_free_llms.py
```

### 3. Run via CLI
```bash
nexus run --target localhost
nexus tools
nexus agents
nexus providers
```

---

## ⚖️ Legal & Ethical Disclaimer

NEXUS-STRIKE is intended **ONLY** for legal, authorized security testing, educational research, and defensive security auditing. 

Users must obtain explicit written permission from system owners prior to running scans or security tests against any external target. The developers assume no liability for misuse or damage caused by this program.

---

## 📜 License

[MIT License](LICENSE) — Feel free to clone, fork, modify, and contribute!