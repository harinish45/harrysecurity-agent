#!/usr/bin/env python3
"""
NEXUS-STRIKE Live Cybersecurity Agent — OmniRoute Edition
==========================================================
Uses OmniRoute (http://127.0.0.1:20128) as the AI gateway,
auto-routing to the best available free model.
Executes REAL tools: port scan, banner grab, DNS, HTTP fingerprint, SSL inspect.
Target: localhost (127.0.0.1)
"""

import sys
import os
import socket
import ssl
import json
import time
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# LLM backend — use OmniRoute if configured, fall back to Ollama
LLM_URL   = os.getenv("CUSTOM_BASE_URL") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
LLM_MODEL = os.getenv("CUSTOM_MODEL") or os.getenv("OLLAMA_MODEL", "qwen2.5-coder:latest")
LLM_KEY   = os.getenv("CUSTOM_API_KEY") or "ollama"  # OmniRoute key or dummy
TARGET       = "127.0.0.1"
TARGET_HOST  = "localhost"
TIMEOUT      = 1.0
TOP_PORTS    = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 3000, 3306, 3389, 4000,
    5000, 5432, 5900, 6379, 7070, 8000, 8080, 8443, 8888, 9000,
    9090, 9200, 27017, 27018, 50000,
]


def llm(prompt, system="You are a senior penetration tester."):
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
        "stream": False,
    }
    try:
        resp = requests.post(
            f"{LLM_URL}/chat/completions",
            headers={"Authorization": f"Bearer {LLM_KEY}"},
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return f"[LLM ERROR] {exc}"


def tool_port_scan(host, ports):
    def probe(port):
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                return port
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        results = list(ex.map(probe, ports))
    open_ports = sorted(p for p in results if p is not None)
    return {"open_ports": open_ports, "findings": [f"Open port: {p}" for p in open_ports]}


def tool_banner_grab(host, ports):
    banners = {}
    for port in ports[:10]:
        try:
            with socket.create_connection((host, port), timeout=2) as sock:
                sock.settimeout(2)
                try:
                    if port in (80, 8080, 8000, 3000, 4000, 5000, 8443, 8888, 9000, 9090):
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    data = sock.recv(256)
                    banners[port] = data.decode("utf-8", errors="replace").strip()[:120]
                except socket.timeout:
                    banners[port] = "<no banner>"
        except Exception:
            pass
    return {"banners": banners, "findings": [f"Port {p} banner: {b}" for p, b in banners.items()]}


def tool_dns_recon(host):
    findings = []
    try:
        ip = socket.gethostbyname(host)
        findings.append(f"Resolved {host} -> {ip}")
        try:
            rev = socket.gethostbyaddr(ip)[0]
            findings.append(f"Reverse DNS: {ip} -> {rev}")
        except Exception:
            findings.append(f"No PTR record for {ip}")
    except Exception as exc:
        findings.append(f"DNS failed: {exc}")
    return {"findings": findings}


def tool_http_fingerprint(host, ports):
    findings = []
    http_ports = [p for p in ports if p in
                  (80, 443, 8080, 8000, 8443, 3000, 4000, 5000, 7070, 8888, 9000, 9090, 9200)]
    for port in http_ports[:6]:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
                server  = resp.headers.get("Server", "unknown")
                powered = resp.headers.get("X-Powered-By", "")
                status  = resp.status
                line = f"HTTP {port}: status={status}, Server={server}"
                if powered:
                    line += f", X-Powered-By={powered}"
                findings.append(line)
        except urllib.error.HTTPError as e:
            findings.append(f"HTTP {port}: HTTP {e.code} ({url})")
        except Exception as exc:
            findings.append(f"HTTP {port}: {str(exc)[:80]}")
    return {"findings": findings}


def tool_ssl_inspect(host, ports):
    findings = []
    ssl_ports = [p for p in ports if p in (443, 8443, 465, 993, 995)]
    for port in ssl_ports[:3]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert   = s.getpeercert()
                    cipher = s.cipher()
                    proto  = s.version()
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    expiry  = cert.get("notAfter", "unknown")
                    findings.append(
                        f"SSL port {port}: proto={proto}, cipher={cipher[0]}, "
                        f"CN={subject.get('commonName','?')}, "
                        f"issuer={issuer.get('organizationName','?')}, expires={expiry}"
                    )
        except Exception as exc:
            findings.append(f"SSL {port}: {str(exc)[:100]}")
    return {"findings": findings}


def tool_service_map(open_ports):
    known = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
        110:"POP3",111:"RPC",135:"MS-RPC",139:"NetBIOS",143:"IMAP",
        443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP-TLS",631:"IPP",
        993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",
        3000:"Dev-HTTP",3306:"MySQL",3389:"RDP",4000:"Dev-HTTP",
        5000:"Dev-HTTP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",
        7070:"Dev-HTTP",8000:"Dev-HTTP",8080:"HTTP-Alt",8443:"HTTPS-Alt",
        8888:"Jupyter/Dev",9000:"Dev-HTTP",9090:"Dev-HTTP",
        9200:"Elasticsearch",27017:"MongoDB",27018:"MongoDB",
    }
    services = {p: known.get(p, "Unknown") for p in open_ports}
    return {"services": services, "findings": [f"Port {p}: {s}" for p, s in services.items()]}


def sep(title="", width=68):
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'=' * pad} {title} {'=' * pad}")
    else:
        print("=" * width)


def main(target: str = "127.0.0.1", host: str = "localhost"):
    global TARGET, TARGET_HOST
    TARGET = target
    TARGET_HOST = host
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 68)
    print(f"  NEXUS-STRIKE  Live AI Cybersecurity Agent")
    print(f"  LLM Gateway : OmniRoute -> {LLM_URL}")
    print(f"  LLM Model   : {LLM_MODEL}")
    print(f"  Target    : {TARGET_HOST} ({TARGET})")
    print(f"  Started   : {ts}")
    print("=" * 68)

    all_findings = []
    analysis_blocks = []

    # Phase 1: AI planning
    sep("PHASE 1 - AI Mission Planning")
    print("  [*] Asking Ollama to plan the assessment...")
    plan = llm(
        "I am about to run a security assessment on localhost (127.0.0.1). "
        "What are the 5 most important things to check? List them briefly, numbered.",
        system="You are a penetration tester. Be brief and technical.",
    )
    print(f"\n{plan}\n")

    # Phase 2: Port scan
    sep("PHASE 2 - TCP Port Scan")
    print(f"  [*] Scanning {len(TOP_PORTS)} ports on {TARGET}...")
    t0 = time.time()
    ps = tool_port_scan(TARGET, TOP_PORTS)
    elapsed = round(time.time() - t0, 2)
    open_ports = ps["open_ports"]
    all_findings.extend(ps["findings"])
    if open_ports:
        print(f"  [+] Open ports ({elapsed}s): {open_ports}")
    else:
        print(f"  [-] No open ports found ({elapsed}s)")

    # Phase 3: Service map
    sep("PHASE 3 - Service Identification")
    svc = tool_service_map(open_ports)
    all_findings.extend(svc["findings"])
    for f in svc["findings"]:
        print(f"  [+] {f}")

    # Phase 4: Banner grab
    sep("PHASE 4 - Banner Grabbing")
    bg = {"findings": []}
    if open_ports:
        bg = tool_banner_grab(TARGET, open_ports)
        all_findings.extend(bg["findings"])
        for f in bg["findings"]:
            print(f"  [+] {f}")
    else:
        print("  [-] No open ports to grab banners from")

    # Phase 5: DNS recon
    sep("PHASE 5 - DNS Reconnaissance")
    dns = tool_dns_recon(TARGET_HOST)
    all_findings.extend(dns["findings"])
    for f in dns["findings"]:
        print(f"  [+] {f}")

    # Phase 6: HTTP fingerprint
    sep("PHASE 6 - HTTP Fingerprinting")
    http = {"findings": []}
    if open_ports:
        http = tool_http_fingerprint(TARGET, open_ports)
        all_findings.extend(http["findings"])
        for f in http["findings"]:
            print(f"  [+] {f}")
    else:
        print("  [-] No open ports to fingerprint")

    # Phase 6.5: SQLi detection (via tool registry)
    sep("PHASE 6.5 - SQL Injection Detection (Tool Fabric)")
    sqli_findings = []
    if open_ports:
        # Ensure nexus package is importable
        _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _project_root not in sys.path:
            sys.path.insert(0, _project_root)
        try:
            from nexus.tools.webapp.sqli import run as sqli_run
        except ImportError:
            sqli_run = None

        if sqli_run:
            http_ports = [p for p in open_ports if p in
                          (80, 443, 8080, 8000, 8443, 3000, 4000, 5000,
                           7070, 8888, 9000, 9090, 9200)]
            for port in http_ports[:3]:
                scheme = "https" if port in (443, 8443) else "http"
                test_url = f"{scheme}://{TARGET}:{port}/?id=1"
                print(f"  [*] Testing {test_url} for SQLi...")
                try:
                    result = sqli_run(target=test_url)
                    if result.get("findings"):
                        sqli_findings.extend(result["findings"])
                        for f in result["findings"]:
                            print(f"  [!] {f}")
                    else:
                        print(f"  [+] No SQLi detected on port {port}")
                except Exception as exc:
                    print(f"  [-] SQLi test failed on port {port}: {exc}")
        else:
            print("  [-] nexus.tools.webapp.sqli not importable")
        all_findings.extend(sqli_findings)
    else:
        print("  [-] No HTTP ports to test for SQLi")

    # Phase 7: SSL inspection
    sep("PHASE 7 - SSL/TLS Inspection")
    ssl_res = tool_ssl_inspect(TARGET, open_ports)
    all_findings.extend(ssl_res["findings"])
    if ssl_res["findings"]:
        for f in ssl_res["findings"]:
            print(f"  [+] {f}")
    else:
        print("  [-] No SSL ports found")

    # Phase 8: AI risk analysis
    sep("PHASE 8 - AI Risk Analysis (Ollama)")
    print("  [*] Analysing findings with Ollama...")
    if open_ports:
        port_analysis = llm(
            f"Penetration test on localhost found these open ports and services:\n"
            f"{json.dumps(svc['services'], indent=2)}\n\n"
            f"Banners:\n{chr(10).join(bg['findings'])}\n\n"
            f"HTTP results:\n{chr(10).join(http['findings'])}\n\n"
            f"SQLi results:\n{chr(10).join(sqli_findings) if sqli_findings else 'No SQLi detected'}\n\n"
            "Identify: 1) High-risk services, 2) Attack vectors, 3) Recommended next steps. Be concise.",
        )
    else:
        port_analysis = llm(
            "A port scan on localhost found NO open ports. "
            "What could be causing this? What should we try next?",
        )
    analysis_blocks.append(port_analysis)
    print(f"\n{port_analysis}\n")

    # Phase 8.5: CVE enrichment (offline knowledge base)
    sep("PHASE 8.5 - CVE Enrichment (Local KB)")
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
        from cve_enhance import enrich_findings, format_for_llm
        enriched = enrich_findings(all_findings)
        cve_text = format_for_llm(enriched)
        print(cve_text)
    except Exception as exc:
        print(f"  [-] CVE enrichment skipped: {exc}")
        cve_text = "CVE enrichment unavailable."
        enriched = []

    # Phase 9: Final report
    sep("PHASE 9 - Final Pentest Report (Ollama)")
    print("  [*] Generating security report with Ollama...")
    report = llm(
        f"Write a professional penetration test report for localhost (127.0.0.1), "
        f"date {datetime.now().strftime('%Y-%m-%d')}.\n\n"
        f"FINDINGS:\n{chr(10).join(all_findings[:50])}\n\n"
        f"ANALYSIS:\n{chr(10).join(analysis_blocks)}\n\n"
        f"CVE ENRICHMENT:\n{cve_text}\n\n"
        "Format: Executive Summary, Scope, Findings (with severity and CVE IDs), Recommendations, Conclusion.",
        system="You are a senior penetration tester writing a professional security report.",
    )
    print(f"\n{report}\n")

    # Summary
    sep("MISSION COMPLETE")
    print(f"  Total findings : {len(all_findings)}")
    print(f"  Open ports     : {open_ports or 'none detected'}")
    print(f"  LLM provider   : OmniRoute ({LLM_MODEL})")
    print(f"  Completed at   : {datetime.now().strftime('%H:%M:%S')}")
    sep()


if __name__ == "__main__":
    main()
