#!/usr/bin/env python3
"""
NEXUS-STRIKE — 11-Phase AI-Powered Security Scanner
====================================================
Phases:
  1. AI Mission Planning
  2. TCP Port Scan
  3. Service Identification
  4. Banner Grabbing
  5. DNS Reconnaissance
  6. HTTP Fingerprinting
  6.5 SQL Injection Detection
  7. SSL/TLS Inspection
  8. AI Risk Analysis
  8.5 CVE Enrichment
  9. Final Report (LLM)

Target override via --target or target_ip parameter.
"""
from __future__ import annotations

import os
import sys
import time
import json
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
from datetime import datetime
from typing import Any
from nexus.foundation.ssl_config import get_ssl_context

# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from nexus.foundation.config import config
from nexus.foundation.guardrails import LegalGuard, ScopeGuard
from nexus.foundation.logging import logger
from nexus.intelligence.llm.router import LLMRouter

# ---------------------------------------------------------------------------
# Globals (allow caller override)
# ---------------------------------------------------------------------------
TARGET: str = "127.0.0.1"
TARGET_HOST: str = "localhost"
LLM_URL: str = getattr(config, "ollama_base_url", "http://localhost:11434/v1")
LLM_MODEL: str = getattr(config, "ollama_model", "qwen2.5-coder:7b")
LLM_KEY: str = os.getenv("CUSTOM_API_KEY") or os.getenv("OLLAMA_API_KEY") or "ollama"
TIMEOUT: float = 2.0

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 465, 587, 631, 993, 995, 1433, 1521, 3000,
    3306, 3389, 4000, 5000, 5432, 5900, 6379, 7070, 8000, 8080,
    8443, 8888, 9000, 9090, 9200, 27017, 27018, 50000,
]

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submit", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "OracleDB",
    3000: "Dev-HTTP (Node/React)", 3306: "MySQL", 3389: "RDP", 4000: "Dev-HTTP",
    5000: "Dev-HTTP (Flask)", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7070: "Dev-HTTP", 8000: "Dev-HTTP (Django/FastAPI)", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "Jupyter/Dev", 9000: "Dev-HTTP (PHP-FPM/SonarQube)", 9090: "Dev-HTTP (Prometheus/Cockpit)", 9200: "Elasticsearch",
    27017: "MongoDB", 27018: "MongoDB-Shard", 50000: "DB2",
}


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------
def llm(prompt: str, system: str = "You are a senior penetration tester.", temperature: float = 0.2) -> str:
    """Call Ollama (or configured provider) and return text."""
    router = LLMRouter()
    try:
        return router.complete(
            prompt,
            system=system,
            temperature=temperature,
            max_tokens=1024,
        )
    except Exception as exc:
        return f"[LLM ERROR] {exc}"


# ---------------------------------------------------------------------------
# Tool helpers
# ---------------------------------------------------------------------------
def _probe_port(host: str, port: int, timeout: float = TIMEOUT) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _grab_banner(sock, port)
            tls = _check_tls(host, port, timeout)
            return {
                "port": port,
                "state": "open",
                "service": KNOWN_SERVICES.get(port, "unknown"),
                "banner": banner or "",
                "tls": tls,
            }
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass
    return None


def _grab_banner(sock: socket.socket, port: int, max_bytes: int = 4096) -> str:
    try:
        if port in (21, 25, 110, 143, 220, 993, 995):
            sock.sendall(b"\r\n")
        elif port in (80, 8080, 8000, 443, 8443):
            sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        data = sock.recv(max_bytes)
        return data.decode("utf-8", errors="replace").strip()[:512]
    except OSError:
        return ""


def _check_tls(host: str, port: int, timeout: float) -> dict:
    if port not in (443, 8443, 993, 995, 465, 636, 587):
        return {}
    try:
        ctx = get_ssl_context(host, allow_insecure=True)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=True)
                if not cert:
                    return {"available": True, "cert": None}
                version = tls_sock.version()
                cipher = tls_sock.cipher()
                return {
                    "available": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[1] if cipher else 0,
                }
    except Exception:
        return {"available": False}


def _http_request(url: str, timeout: int = 10, method: str = "GET", data: bytes = None) -> dict:
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/1.0"}, method=method, data=data)
        ctx = get_ssl_context(url, allow_insecure=True)
        t0 = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        elapsed = round(time.time() - t0, 3)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "headers": dict(resp.headers), "body": body, "time": elapsed, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "headers": dict(e.headers), "body": body, "time": 0, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "time": 0, "error": str(e)[:100]}


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------
def phase1_ai_planning(target: str, host: str) -> str:
    print("\n" + "=" * 68)
    print("  PHASE 1 — AI Mission Planning")
    print("=" * 68)
    print(f"  [*] Asking {LLM_MODEL} to plan assessment on {host} ({target})...")
    prompt = (
        f"I am running a security assessment on {host} ({target}). "
        "What are the 5 most important things to check? List them briefly, numbered."
    )
    plan = llm(prompt, system="You are a penetration tester. Be brief and technical.")
    print(f"\n{plan}\n")
    return plan


def phase2_port_scan(target: str) -> tuple[list[dict], list[int]]:
    print("\n" + "=" * 68)
    print("  PHASE 2 — TCP Port Scan")
    print("=" * 68)
    print(f"  [*] Scanning {len(TOP_PORTS)} ports on {target}...")
    t0 = time.time()
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        fut_map = {ex.submit(_probe_port, target, p, TIMEOUT): p for p in TOP_PORTS}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                res = fut.result()
                if res:
                    open_ports.append(res)
            except Exception:
                pass
    open_ports.sort(key=lambda x: x["port"])
    elapsed = round(time.time() - t0, 2)
    port_nums = [p["port"] for p in open_ports]
    if open_ports:
        print(f"  [+] Open ports ({elapsed}s): {port_nums}")
    else:
        print(f"  [-] No open ports found ({elapsed}s)")
    return open_ports, port_nums


def phase3_service_map(open_ports: list[dict]) -> dict:
    print("\n" + "=" * 68)
    print("  PHASE 3 — Service Identification")
    print("=" * 68)
    services = {p["port"]: p["service"] for p in open_ports}
    for port, svc in sorted(services.items()):
        print(f"  [+] {port}/{svc}")
    return services


def phase4_banner_grab(target: str, open_ports: list[dict]) -> list[str]:
    print("\n" + "=" * 68)
    print("  PHASE 4 — Banner Grabbing")
    print("=" * 68)
    findings = []
    for p in open_ports[:20]:
        port = p["port"]
        try:
            with socket.create_connection((target, port), timeout=2) as sock:
                sock.settimeout(2)
                if port in (80, 8080, 8000, 443, 8443):
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = sock.recv(4096)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
                if banner:
                    findings.append(f"Port {port} banner: {banner}")
                    print(f"  [+] Port {port}: {banner[:80]}")
        except Exception:
            pass
    if not findings:
        print("  [-] No banners retrieved")
    return findings


def phase5_dns_recon(host: str) -> list[str]:
    print("\n" + "=" * 68)
    print("  PHASE 5 — DNS Reconnaissance")
    print("=" * 68)
    findings = []
    try:
        ip = socket.gethostbyname(host)
        findings.append(f"Resolved {host} -> {ip}")
        print(f"  [+] {host} -> {ip}")
        try:
            rev = socket.gethostbyaddr(ip)[0]
            findings.append(f"Reverse DNS: {ip} -> {rev}")
            print(f"  [+] Reverse: {ip} -> {rev}")
        except Exception:
            findings.append(f"No PTR record for {ip}")
            print(f"  [-] No PTR record for {ip}")
    except Exception as exc:
        findings.append(f"DNS failed: {exc}")
        print(f"  [-] DNS failed: {exc}")
    return findings


def phase6_http_fingerprint(target: str, open_ports: list[dict]) -> list[str]:
    print("\n" + "=" * 68)
    print("  PHASE 6 — HTTP Fingerprinting")
    print("=" * 68)
    findings = []
    http_ports = [p["port"] for p in open_ports if p["port"] in (80, 443, 8080, 8000, 8443, 3000, 4000, 5000, 7070, 8888, 9000, 9090, 9200)]
    for port in http_ports[:6]:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target}:{port}/"
        resp = _http_request(url, timeout=4)
        if resp["status"] and resp["status"] != 0:
            server = resp["headers"].get("Server", "unknown")
            powered = resp["headers"].get("X-Powered-By", "")
            line = f"HTTP {port}: status={resp['status']}, Server={server}"
            if powered:
                line += f", X-Powered-By={powered}"
            findings.append(line)
            print(f"  [+] {line}")
        else:
            print(f"  [-] HTTP {port}: {resp.get('error', 'no response')}")
    if not findings:
        print("  [-] No HTTP ports found")
    return findings


def phase6_sqli_detection(target: str, open_ports: list[dict]) -> list[str]:
    print("\n" + "=" * 68)
    print("  PHASE 6.5 — SQL Injection Detection")
    print("=" * 68)
    findings = []
    http_ports = [p["port"] for p in open_ports if p["port"] in (80, 443, 8080, 8000, 8443, 3000, 4000, 5000, 7070, 8888, 9000, 9090, 9200)]
    if not http_ports:
        print("  [-] No HTTP ports to test")
        return findings

    from nexus.tools.registry import tool_registry

    if "webapp.sqli" not in tool_registry.list_tools():
        print("  [-] webapp.sqli not registered")
        return findings

    for port in http_ports[:3]:
        scheme = "https" if port in (443, 8443) else "http"
        test_url = f"{scheme}://{target}:{port}/?id=1"
        print(f"  [*] Testing {test_url} for SQLi...")
        try:
            # Routed through the guardrailed registry (not a raw import) —
            # this is an active SQL-injection probe, so it must go through
            # RateGuard/EscalationGuard/AuditGuard like every other tool call.
            result = tool_registry.run("webapp.sqli", target=test_url)
            if result.get("status") == "failed" and "approval" in (result.get("error") or "").lower():
                print(f"  [-] SQLi test on port {port} requires approval: {result.get('error')}")
                print("      Set ESCALATION_APPROVED=true to allow active SQLi probing.")
            elif result.get("findings"):
                for f in result["findings"]:
                    text = f.get("evidence", f.get("title", str(f)))
                    findings.append(text)
                    print(f"  [!] {text}")
            else:
                print(f"  [+] No SQLi detected on port {port}")
        except Exception as exc:
            print(f"  [-] SQLi test failed on port {port}: {exc}")
    return findings


def phase7_ssl_inspect(target: str, open_ports: list[dict]) -> list[str]:
    print("\n" + "=" * 68)
    print("  PHASE 7 — SSL/TLS Inspection")
    print("=" * 68)
    findings = []
    ssl_ports = [p["port"] for p in open_ports if p["port"] in (443, 8443, 465, 993, 995)]
    for port in ssl_ports[:3]:
        try:
            ctx = get_ssl_context(target, allow_insecure=True)
            with socket.create_connection((target, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as s:
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    proto = s.version()
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    expiry = cert.get("notAfter", "unknown")
                    line = (
                        f"SSL {port}: proto={proto}, cipher={cipher[0]}, "
                        f"CN={subject.get('commonName','?')}, "
                        f"issuer={issuer.get('organizationName','?')}, expires={expiry}"
                    )
                    findings.append(line)
                    print(f"  [+] {line}")
        except Exception as exc:
            findings.append(f"SSL {port}: {str(exc)[:100]}")
            print(f"  [-] SSL {port}: {str(exc)[:100]}")
    if not findings:
        print("  [-] No SSL ports found")
    return findings


def phase8_risk_analysis(all_findings: list[str], services: dict, banners: list[str], http: list[str], sql: list[str]) -> str:
    print("\n" + "=" * 68)
    print("  PHASE 8 — AI Risk Analysis")
    print("=" * 68)
    print("  [*] Analysing findings with LLM...")
    context = (
        f"Services: {json.dumps(services, indent=2)}\n\n"
        f"Banners:\n{chr(10).join(banners)}\n\n"
        f"HTTP results:\n{chr(10).join(http)}\n\n"
        f"SQLi results:\n{chr(10).join(sql) if sql else 'No SQLi detected'}\n\n"
        "Identify: 1) High-risk services, 2) Attack vectors, 3) Recommended next steps. Be concise."
    )
    analysis = llm(context, system="You are a penetration tester. Be brief and technical.")
    print(f"\n{analysis}\n")
    return analysis


def phase8_cve_enrichment(all_findings: list[str]) -> tuple[str, list]:
    print("\n" + "=" * 68)
    print("  PHASE 8.5 — CVE Enrichment (Local KB)")
    print("=" * 68)
    try:
        from cve_enhance import enrich_findings, format_for_llm
        enriched = enrich_findings(all_findings)
        cve_text = format_for_llm(enriched)
        print(cve_text)
        return cve_text, enriched
    except Exception as exc:
        print(f"  [-] CVE enrichment skipped: {exc}")
        return "CVE enrichment unavailable.", []


def phase9_final_report(target: str, host: str, findings: list[str], analysis: str, cve_text: str) -> str:
    print("\n" + "=" * 68)
    print("  PHASE 9 — Final Report (LLM)")
    print("=" * 68)
    print("  [*] Generating security report with LLM...")
    report_prompt = (
        f"Write a professional penetration test report for {host} ({target}), "
        f"date {datetime.now().strftime('%Y-%m-%d')}.\n\n"
        f"FINDINGS:\n{chr(10).join(findings[:50])}\n\n"
        f"ANALYSIS:\n{analysis}\n\n"
        f"CVE ENRICHMENT:\n{cve_text}\n\n"
        "Format: Executive Summary, Scope, Findings (with severity and CVE IDs), Recommendations, Conclusion."
    )
    report = llm(report_prompt, system="You are a senior penetration tester writing a professional security report.")
    print(f"\n{report}\n")
    return report


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def run_assessment(target_ip: str, target_host: str | None = None) -> dict:
    """Run the full 11-phase assessment pipeline.

    Returns dict with keys: findings, llm_blocks, phases, cve_text, sql_findings,
    open_ports, services, all_findings, _meta.
    """
    global TARGET, TARGET_HOST
    TARGET = target_ip
    TARGET_HOST = target_host or target_ip

    # This is a real, standalone entrypoint (invoked directly via `nexus live`,
    # not only through the dashboard's own pre-check in web/server.py's
    # /api/scan/start) that actively probes a target, including firing SQL
    # injection payloads in phase 6.5 — it must not be reachable without
    # scope/legal validation of its own, the same as every other mission path.
    try:
        ScopeGuard.validate(TARGET)
        LegalGuard.validate(target=TARGET)
    except Exception as exc:
        print(f"\n[!] Guardrail blocked this scan: {exc}")
        return {
            "findings": [], "llm_blocks": [], "phases": [], "cve_text": "", "sql_findings": [],
            "open_ports": [], "services": {}, "all_findings": [],
            "_meta": {"target": TARGET, "target_host": TARGET_HOST, "status": "blocked", "error": str(exc)},
        }

    started = time.time()
    findings: list[str] = []
    llm_blocks: list[str] = []
    phases: list[str] = []
    sql_findings: list[str] = []
    open_ports_data: list[dict] = []
    services: dict = {}
    cve_text = ""
    enriched_cves = []

    print("\n" + "#" * 68)
    print(f"  NEXUS-STRIKE  11-Phase AI Scanner")
    print(f"  Target: {TARGET_HOST} ({TARGET})")
    print(f"  LLM:    {LLM_MODEL} @ {LLM_URL}")
    print(f"  Started:{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("#" * 68)

    try:
        # Phase 1
        plan = phase1_ai_planning(TARGET, TARGET_HOST)
        llm_blocks.append(plan)
        phases.append("AI Mission Planning")

        # Phase 2
        open_ports_data, open_port_nums = phase2_port_scan(TARGET)
        findings.append(f"Open ports: {open_port_nums}")
        phases.append("TCP Port Scan")

        # Phase 3
        services = phase3_service_map(open_ports_data)
        phases.append("Service Identification")

        # Phase 4
        banners = phase4_banner_grab(TARGET, open_ports_data)
        findings.extend(banners)
        phases.append("Banner Grabbing")

        # Phase 5
        dns = phase5_dns_recon(TARGET_HOST)
        findings.extend(dns)
        phases.append("DNS Reconnaissance")

        # Phase 6
        http = phase6_http_fingerprint(TARGET, open_ports_data)
        findings.extend(http)
        phases.append("HTTP Fingerprinting")

        # Phase 6.5
        sql_findings = phase6_sqli_detection(TARGET, open_ports_data)
        findings.extend(sql_findings)
        phases.append("SQL Injection Detection")

        # Phase 7
        ssl_findings = phase7_ssl_inspect(TARGET, open_ports_data)
        findings.extend(ssl_findings)
        phases.append("SSL/TLS Inspection")

        # Phase 8
        analysis = phase8_risk_analysis(findings, services, banners, http, sql_findings)
        llm_blocks.append(analysis)
        phases.append("AI Risk Analysis")

        # Phase 8.5
        cve_text, enriched_cves = phase8_cve_enrichment(findings)
        phases.append("CVE Enrichment")

        # Phase 9
        report = phase9_final_report(TARGET, TARGET_HOST, findings, analysis, cve_text)
        llm_blocks.append(report)
        phases.append("Final Report")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as exc:
        print(f"\n[!] Pipeline error: {exc}")

    elapsed = round(time.time() - started, 1)
    print("\n" + "#" * 68)
    print(f"  MISSION COMPLETE  ({elapsed}s)")
    print(f"  Findings  : {len(findings)}")
    print(f"  Open ports: {[p['port'] for p in open_ports_data] or 'none'}")
    print(f"  LLM blocks: {len(llm_blocks)}")
    print("#" * 68)

    return {
        "findings": findings,
        "llm_blocks": llm_blocks,
        "phases": phases,
        "cve_text": cve_text,
        "sql_findings": sql_findings,
        "open_ports": [p["port"] for p in open_ports_data],
        "services": services,
        "all_findings": findings,
        "_meta": {
            "target": TARGET,
            "target_host": TARGET_HOST,
            "started_at": datetime.now().isoformat(),
            "elapsed_seconds": elapsed,
            "operator": os.getenv("USERNAME", "HARINISH"),
            "llm_model": LLM_MODEL,
            "llm_url": LLM_URL,
            "phases_completed": len(phases),
            "cve_count": len(enriched_cves),
        },
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="NEXUS-STRIKE 11-Phase AI Scanner")
    parser.add_argument("--target", "-t", default=None, help="Target IP or hostname")
    parser.add_argument("--host", "-H", default=None, help="Target hostname for DNS")
    args = parser.parse_args()

    target = args.target or TARGET
    host = args.host or target
    result = run_assessment(target_ip=target, target_host=host)
    return result


if __name__ == "__main__":
    main()