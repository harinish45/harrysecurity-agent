# Quick Start Guide

NEXUS-STRIKE is an AI-powered cybersecurity platform for penetration testing, bug bounty, and security assessments.

## Installation

```bash
git clone https://github.com/nexus-strike/nexus-strike.git
cd nexus-strike
pip install -e .
```

## Prerequisites

1. **Python 3.10+** installed and on PATH
2. **Legal authorization** — set `NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION` in your environment
3. **Target scope** — set `NEXUS_ALLOWED_TARGETS` to approved targets
4. **LLM provider** — optionally configure Ollama for AI-powered planning

## Basic Usage

### 1. Create an engagement record

```bash
nexus engage \
  --client "Acme Corp" \
  --scope "example.com,api.example.com" \
  --authorization-reference "TICKET-1234" \
  --asset-owner "security@acme.com" \
  --emergency-stop "1-800-SECURITY"
```

### 2. Run a security assessment

```bash
# Scan a single target
nexus run --target example.com --engagement engagements/engagement-*.json

# Quick scan
nexus run --target example.com --objective quick_scan

# Full assessment with autonomous mode
nexus run --target example.com --mode autonomous --objective full_assessment
```

### 3. Live AI Agent (standalone)

```bash
# Scan localhost
python scripts/live_agent.py

# Scan a specific target
python scripts/live_agent.py --target 192.168.1.1 --host target.example.com

# Custom ports
python scripts/live_agent.py --target 10.0.0.1 --ports "22,80,443,8080"
```

### 4. Check readiness

```bash
nexus preflight --strict
```

### 5. Export findings

```bash
nexus export-report findings.json --format html --output report.html
nexus export-report findings.json --format sarif --output report.sarif
nexus export-report findings.json --format csv --output report.csv
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `nexus run` | Launch a security assessment mission |
| `nexus engage` | Create an engagement record |
| `nexus preflight` | Check local readiness |
| `nexus live` | Run the live AI cybersecurity agent |
| `nexus tools` | List registered tools |
| `nexus agents` | List registered agents |
| `nexus providers` | Show LLM provider status |
| `nexus verify` | Offline integrity check |
| `nexus export-report` | Export findings to file |
| `nexus config` | Show configuration |
| `nexus version` | Show version info |

## Configuration

Set environment variables in `.env`:

```bash
NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION
NEXUS_ALLOWED_TARGETS=example.com,api.example.com
NEXUS_LLM_PROVIDER=ollama
NEXUS_OLLAMA_BASE_URL=http://localhost:11434/v1
```

## What Gets Scanned

NEXUS-STRIKE covers 29 security domains with 264 tools:

- **Network**: Port scanning, service enumeration, OS fingerprinting, banner grabbing
- **Web/API**: SQL injection, XSS, SSRF, LFI, RFI, command injection, directory enumeration
- **Reconnaissance**: Subdomain enumeration, DNS reconnaissance, technology fingerprinting
- **Cloud**: AWS/Azure/GCP configuration review
- **Forensics**: Log analysis, IOC matching, timeline correlation
- **AppSec**: Secret scanning, dependency analysis, SAST
- **Wireless, Mobile, Malware, Reverse Engineering** and more
