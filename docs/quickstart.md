# Quick Start

## Prerequisites

- Python 3.10+
- pip

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/nexus-strike.git
cd nexus-strike

# Install in development mode
pip install -e .

# Copy and configure environment
cp .env.example .env
```

## Configuration

Edit `.env` to set your LLM provider:

```bash
# For local LLM (Ollama)
LLM_PROVIDER=ollama
OLLAMA_MODEL=qwen2.5-coder:latest

# For OpenAI
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# For OmniRoute
LLM_PROVIDER=custom
CUSTOM_BASE_URL=http://127.0.0.1:20128
CUSTOM_MODEL=gpt-4
```

## Running Your First Assessment

### Using `nexus live` (real tools, recommended)

```bash
# Scan localhost
nexus live --target 127.0.0.1

# Scan a remote target
nexus live --target 192.168.1.1 --host example.com

# With custom ports
nexus live --target 10.0.0.1 --ports 80,443,8080,8443

# With custom LLM
nexus live --target scanme.nmap.org --llm-url http://localhost:11434/v1 --llm-model llama3
```

### Using `nexus run` (orchestration engine)

```bash
# Run a guided assessment
nexus run --target example.com

# With engagement record for authorized testing
nexus engage --client "Client Name" --scope "example.com,192.168.1.0/24" --authorization-reference "TICKET-123"
nexus run --target example.com --engagement engagements/engagement-*.json
```

### Using the standalone script

```bash
# Default: scan localhost
python scripts/live_agent.py

# Scan specific target
python scripts/live_agent.py --target 192.168.1.1 --host example.com

# Show help
python scripts/live_agent.py --help
```

## What Happens During a Scan

The live agent runs these phases automatically:

1. **AI Mission Planning** — LLM plans the assessment strategy
2. **TCP Port Scan** — 39 common ports scanned concurrently
3. **Service Identification** — Maps ports to known services
4. **Banner Grabbing** — Extracts service banners for fingerprinting
5. **DNS Reconnaissance** — Forward/reverse DNS resolution
6. **HTTP Fingerprinting** — Web server detection and header analysis
7. **SQL Injection Detection** — Tests HTTP endpoints for SQLi
8. **SSL/TLS Inspection** — Certificate and cipher analysis
9. **AI Risk Analysis** — LLM analyzes findings for risks
10. **CVE Enrichment** — Local knowledge base enrichment
11. **Final Report** — AI-generated pentest report

## CLI Commands

| Command | Description |
|---------|-------------|
| `nexus live --target X` | Run live agent with real tools |
| `nexus run --target X` | Run orchestration engine |
| `nexus engage` | Create authorized engagement record |
| `nexus preflight` | Check environment readiness |
| `nexus tools` | List all registered tools |
| `nexus agents` | List all registered agents |
| `nexus providers` | Show LLM provider status |
| `nexus config-show` | Show current configuration |
| `nexus verify` | Verify all tools import correctly |
| `nexus export-report` | Export findings to JSON/CSV/HTML/SARIF |

## Next Steps

- Read [Architecture](architecture.md) for system design
- Read [API Reference](api_reference.md) for programmatic usage
- Read [Tool Development](tool_development.md) to create custom tools