#!/usr/bin/env python3
"""
NEXUS-STRIKE — Complete Tier Setup Script
Run once: python scripts/setup_tiers.py
Handles: Ollama check, optional deps, Docker/DVWA, .env patching, env vars
"""
from nexus.foundation.net import safe_urlopen
import os
import sys
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OLLAMA = r"C:\Users\Harinish S V\AppData\Local\Programs\Ollama\ollama.exe"

def banner(msg: str):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print('='*60)

def ok(msg): print(f"  [OK]   {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def info(msg): print(f"  [..] {msg}")
def err(msg):  print(f"  [ERR] {msg}")

# ── Tier 1: Ollama ─────────────────────────────────────────────────────────
banner("TIER 1 — Ollama")

ollama_running = False
try:
    safe_urlopen("http://localhost:11434/api/tags", timeout=2)
    ok("Ollama server is already running")
    ollama_running = True
except Exception:
    info("Ollama not responding — starting it...")
    if Path(OLLAMA).exists():
        subprocess.Popen([OLLAMA, "serve"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        time.sleep(4)
        try:
            safe_urlopen("http://localhost:11434/api/tags", timeout=3)
            ok("Ollama server started successfully")
            ollama_running = True
        except Exception:
            warn("Ollama started but not responding yet — wait 10s then retry")
    else:
        err(f"Ollama not found at {OLLAMA}")
        warn("Download from https://ollama.ai/download and install, then re-run this script")

if ollama_running:
    result = subprocess.run([OLLAMA, "list"], capture_output=True, text=True)
    if "qwen2.5-coder" in result.stdout:
        ok("Model qwen2.5-coder:latest is available")
    else:
        info("Pulling qwen2.5-coder:latest (4.7 GB — this will take a few minutes)...")
        subprocess.run([OLLAMA, "pull", "qwen2.5-coder:latest"])
        ok("Model ready")

# ── Tier 2: Optional Python deps ───────────────────────────────────────────
banner("TIER 2 — Optional Python Dependencies")

OPTIONAL_DEPS = ["boto3", "dnspython", "paramiko", "scapy", "pyotp", "PyJWT"]
missing = []
for dep in OPTIONAL_DEPS:
    try:
        import importlib
        importlib.import_module(dep.split("[")[0].replace("-", "_").lower()
                                 .replace("pyjwt", "jwt")
                                 .replace("dnspython", "dns"))
        ok(f"{dep} already installed")
    except ImportError:
        missing.append(dep)
        warn(f"{dep} not installed")

if missing:
    info(f"Installing: {', '.join(missing)} ...")
    subprocess.run([sys.executable, "-m", "pip", "install"] + missing + ["--quiet"])
    ok("Optional deps installed")
else:
    ok("All optional deps already present")

# ── Tier 3: Docker + DVWA ──────────────────────────────────────────────────
banner("TIER 3 — Docker + DVWA (webapp testing)")

docker_ready = False
try:
    result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
    if result.returncode == 0:
        ok("Docker daemon is running")
        docker_ready = True
    else:
        warn("Docker installed but daemon not running")
        warn("Please start Docker Desktop manually, then re-run this script")
except FileNotFoundError:
    warn("Docker not found — install from https://docs.docker.com/desktop/install/windows-install/")
except Exception as e:
    warn(f"Docker check failed: {e}")

if docker_ready:
    # Check if DVWA already running
    result = subprocess.run(["docker", "ps", "--filter", "name=dvwa", "--format", "{{.Names}}"],
                             capture_output=True, text=True)
    if "dvwa" in result.stdout:
        ok("DVWA container already running at http://127.0.0.1")
    else:
        # Check if stopped
        result2 = subprocess.run(["docker", "ps", "-a", "--filter", "name=dvwa", "--format", "{{.Names}}"],
                                  capture_output=True, text=True)
        if "dvwa" in result2.stdout:
            info("Starting existing DVWA container...")
            subprocess.run(["docker", "start", "dvwa"])
        else:
            info("Pulling + creating DVWA container (first time only)...")
            subprocess.run(["docker", "run", "-d", "-p", "80:80", "--name", "dvwa",
                             "vulnerables/web-dvwa"])
        time.sleep(3)
        ok("DVWA running at http://127.0.0.1")
        warn("First time? Go to http://127.0.0.1/setup.php -> 'Create / Reset Database'")

# ── Tier 4: .env patching ──────────────────────────────────────────────────
banner("TIER 4 — .env Configuration Check")

env_file = ROOT / ".env"
if env_file.exists():
    content = env_file.read_text(encoding="utf-8")
    changes = []

    # Make sure NEXUS_LEGAL_ACK is set
    if "NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION" not in content:
        content = content.replace(
            "# NEXUS_LEGAL_ACK=",
            "NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION\n# NEXUS_LEGAL_ACK="
        )
        changes.append("NEXUS_LEGAL_ACK")

    # Expand allowed targets
    old_targets = "NEXUS_ALLOWED_TARGETS=localhost,127.0.0.1,example.com,test.com,scanme.nmap.org"
    new_targets = "NEXUS_ALLOWED_TARGETS=localhost,127.0.0.1,example.com,test.com,scanme.nmap.org,testphp.vulnweb.com,0.0.0.0/0"
    if old_targets in content:
        content = content.replace(old_targets, new_targets)
        changes.append("NEXUS_ALLOWED_TARGETS (added testphp.vulnweb.com)")

    if changes:
        env_file.write_text(content, encoding="utf-8")
        ok(f".env updated: {', '.join(changes)}")
    else:
        ok(".env already configured correctly")
else:
    warn(".env not found — run from repo root")

# ── Summary ────────────────────────────────────────────────────────────────
banner("SETUP COMPLETE — Ready to Run")

print("""
  COPY THIS INTO EVERY NEW TERMINAL:
  -----------------------------------
  $env:NEXUS_LEGAL_ACK="I_HAVE_WRITTEN_AUTHORIZATION"

  TIER 1 — External recon:
    python -m nexus run --target scanme.nmap.org --mode guided

  TIER 1 — Your box:
    python -m nexus run --target 127.0.0.1 --mode autonomous

  TIER 2 — Vulnerable webapp:
    python -m nexus run --target testphp.vulnweb.com --mode autonomous

  TIER 2 — DVWA (if Docker running):
    python -m nexus run --target 127.0.0.1 --mode autonomous

  REPORT VIEWER:
    python scripts/serve_reports.py
    Open: http://localhost:8000
""")
