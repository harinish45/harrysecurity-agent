#!/usr/bin/env python3
"""
NEXUS-STRIKE — CVE Enrichment Extension
Takes raw recon findings (service + version) and matches them against a
local CVE knowledge base. Adds severity, CVE ID, and remediation hints
so the LLM phases have something concrete to work with.

Offline. No external API. Safe to run against any target you own.

Usage (standalone):
    python scripts/cve_enhance.py "Apache/2.4.49" "PHP/7.4.3" "MySQL/9.6.0"

Usage (inside live_agent.py):
    from cve_enhance import enrich_findings
    enriched = enrich_findings(all_findings)
"""

import re
import sys
import json
from typing import Optional


CVE_DB = {
    "apache": [
        {"version_prefix": "2.4.49", "cves": [
            ("CVE-2021-41773", "CRITICAL", "Path traversal & RCE via crafted URI",
             "Update to 2.4.51+. CVE-2021-41773 allows mapped URI execution of CGI scripts outside directories."),
        ]},
        {"version_prefix": "2.4.50", "cves": [
            ("CVE-2021-42013", "CRITICAL", "Path traversal fix bypass",
             "Update to 2.4.51+. CVE-2021-42013 bypasses the CVE-2021-41773 fix via double-encoded URIs."),
        ]},
        {"version_prefix": "2.4.", "cves": [
            ("CVE-2023-25690", "HIGH", "HTTP Request Smuggling via mod_proxy",
             "Update to 2.4.53+."),
            ("CVE-2022-22720", "HIGH", "HTTP Request Smuggling via failed request body",
             "Update to 2.4.53+."),
            ("CVE-2022-22719", "MEDIUM", "mod_lua body init failure",
             "Update to 2.4.53+."),
        ]},
    ],
    "php": [
        {"version_prefix": "5.", "cves": [
            ("CVE-2019-11043", "CRITICAL", "PHP-FPM buffer overflow under nginx",
             "Upgrade to PHP 7.x."),
        ]},
        {"version_prefix": "7.4.", "cves": [
            ("CVE-2022-31628", "HIGH", "Buffer overflow in mysqlnd",
             "Update to 7.4.30+."),
            ("CVE-2022-31629", "HIGH", "Cookie handling bypass",
             "Update to 7.4.30+."),
        ]},
        {"version_prefix": "7.3.", "cves": [
            ("CVE-2021-21707", "CRITICAL", "Use-after-free in stream filter",
             "Update to 7.3.29+ or 8.x."),
        ]},
        {"version_prefix": "7.2.", "cves": [
            ("CVE-2019-11043", "CRITICAL", "PHP-FPM buffer overflow", "End-of-life. Upgrade."),
        ]},
        {"version_prefix": "7.1.", "cves": [
            ("CVE-2019-11043", "CRITICAL", "PHP-FPM buffer overflow", "EOL since 2019. Move to 8.x."),
        ]},
        {"version_prefix": "7.0.", "cves": [
            ("CVE-2019-11043", "CRITICAL", "PHP-FPM buffer overflow", "EOL since 2019. Move to 8.x."),
        ]},
        {"version_prefix": "8.0.", "cves": [
            ("CVE-2023-0568", "MEDIUM", "Core: 1-byte array overread in timelib",
             "Update to 8.0.28+/8.1.16+/8.2.3+."),
        ]},
        {"version_prefix": "8.1.", "cves": [
            ("CVE-2023-0568", "MEDIUM", "Core: 1-byte array overread", "Update to 8.1.16+/8.2.3+."),
        ]},
    ],
    "mysql": [
        {"version_prefix": "5.5.", "cves": [
            ("EOL", "HIGH", "End-of-life since 2018", "Upgrade to 8.x."),
        ]},
        {"version_prefix": "5.6.", "cves": [
            ("EOL", "HIGH", "End-of-life since 2021", "Upgrade to 8.x."),
        ]},
        {"version_prefix": "5.7.", "cves": [
            ("CVE-2022-21417", "HIGH", "ECDSA cert validation bypass", "Update to 5.7.39+."),
        ]},
        {"version_prefix": "8.0.", "cves": [
            ("CVE-2023-21962", "MEDIUM", "InnoDB DML perf schema", "Update to 8.0.33+."),
        ]},
        {"version_prefix": "9.0.", "cves": [
            ("INFO", "INFO", "Recent release", "Monitor advisories."),
        ]},
        {"version_prefix": "9.6.", "cves": [
            ("INFO", "INFO", "Recent release — verify auth & exposure",
             "caching_sha2_password is default; ensure 127.0.0.1 binding unless required."),
        ]},
    ],
    "openssh": [
        {"version_prefix": "7.4", "cves": [
            ("CVE-2018-15473", "MEDIUM", "Username enumeration via timing", "Update to 7.7+."),
        ]},
        {"version_prefix": "7.", "cves": [
            ("CVE-2020-15778", "MEDIUM", "scp command injection via backtick", "Patch in 8.3p1+."),
        ]},
        {"version_prefix": "8.5", "cves": [
            ("CVE-2021-41617", "HIGH", "AuthorizedKeysCommand privilege escalation", "Update to 8.8+."),
        ]},
        {"version_prefix": "9.0", "cves": [
            ("CVE-2024-6387", "CRITICAL", "regreSSHion — remote unauth RCE via signal handler race",
             "Update to 9.8p1+. Unauthenticated RCE on glibc Linux."),
        ]},
    ],
    "nginx": [
        {"version_prefix": "1.16.", "cves": [
            ("CVE-2021-23017", "HIGH", "1-byte memory overwrite in resolver", "Update to 1.16.1+ or 1.17.7+."),
        ]},
        {"version_prefix": "1.17.", "cves": [
            ("CVE-2021-23017", "HIGH", "1-byte memory overwrite in resolver", "Update to 1.17.7+."),
        ]},
        {"version_prefix": "1.20.", "cves": [
            ("CVE-2022-41741", "MEDIUM", "Memory corruption in mp4 module", "Update to 1.23.2+."),
        ]},
    ],
    "vsftpd": [
        {"version_prefix": "2.3.4", "cves": [
            ("CVE-2011-2523", "CRITICAL", "Backdoor in vsftpd 2.3.4 — opens shell on port 6200/tcp",
             "EMERGENCY: Metasploitable default. Trivial backdoor; remove immediately."),
        ]},
    ],
    "samba": [
        {"version_prefix": "3.", "cves": [
            ("CVE-2017-7494", "CRITICAL", "SambaCry — RCE via writable share + malicious .so",
             "Update to 4.6.4+/4.5.10+/4.4.14+."),
            ("CVE-2012-1182", "CRITICAL", "Samba ndr_pull subprotocol heap overflow",
             "Update to 3.6.4+."),
        ]},
        {"version_prefix": "4.", "cves": [
            ("CVE-2017-7494", "CRITICAL", "SambaCry (if not patched)", "Verify patch status."),
        ]},
    ],
    "redis": [
        {"version_prefix": "5.", "cves": [
            ("CVE-2022-0543", "CRITICAL", "Lua sandbox escape on Debian-derived packages",
             "Update to 5.0.14+ or use non-Debian package."),
        ]},
    ],
    "wordpress": [
        {"version_prefix": "4.", "cves": [
            ("CVE-2019-17671", "HIGH", "Authenticated RCE via block editor", "Update to 5.2.5+."),
        ]},
        {"version_prefix": "5.0.", "cves": [
            ("CVE-2020-25286", "CRITICAL", "Authenticated RCE via file upload + path traversal",
             "Update to 5.0.2+."),
        ]},
    ],
    "iis": [
        {"version_prefix": "10.0", "cves": [
            ("CVE-2021-31166", "CRITICAL", "HTTP Protocol Stack (http.sys) RCE",
             "Patch Windows. Wormable pre-auth RCE."),
        ]},
        {"version_prefix": "7.5", "cves": [
            ("CVE-2017-7269", "CRITICAL", "WebDAV buffer overflow RCE",
             "Patch Windows. Public Metasploit module."),
        ]},
    ],
}


SERVICE_PATTERNS = [
    (r"Apache[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "apache"),
    (r"PHP[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "php"),
    (r"mysqld?\s*([0-9]+\.[0-9]+\.[0-9]+)", "mysql"),
    (r"MySQL[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "mysql"),
    (r"OpenSSH[_\s]+([0-9]+\.[0-9]+p?[0-9]*)", "openssh"),
    (r"sshd?\s*OpenSSH[_\s]+([0-9]+\.[0-9]+p?[0-9]*)", "openssh"),
    (r"nginx[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "nginx"),
    (r"vsftpd\s+([0-9]+\.[0-9]+\.[0-9]+)", "vsftpd"),
    (r"Samba[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "samba"),
    (r"redis[-_]version[:\s]+([0-9]+\.[0-9]+)", "redis"),
    (r"Redis\s+([0-9]+\.[0-9]+)", "redis"),
    (r"WordPress[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "wordpress"),
    (r"Microsoft-IIS[/\s]+([0-9]+\.[0-9]+)", "iis"),
    (r"Server:\s*Apache[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "apache"),
    (r"X-Powered-By:\s*PHP[/\s]+([0-9]+\.[0-9]+\.[0-9]+)", "php"),
]


def parse_services(text):
    hits = []
    for pattern, key in SERVICE_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            hits.append((key, m.group(1)))
    return hits


def lookup_cves(service, version):
    entries = CVE_DB.get(service.lower(), [])
    hits = []
    for entry in entries:
        if version.startswith(entry["version_prefix"]):
            hits.extend(entry["cves"])
    return hits


def enrich_findings(findings, llm_router=None):
    enriched = []
    seen = set()
    for f in findings or []:
        if not isinstance(f, str):
            continue
        for service, version in parse_services(f):
            key = (service, version)
            if key in seen:
                continue
            seen.add(key)
            cves = lookup_cves(service, version)
            if cves:
                enriched.append({
                    "service": service, "version": version,
                    "cves": cves, "source": f,
                })
            elif service in CVE_DB:
                enriched.append({
                    "service": service, "version": version,
                    "cves": [("INFO", "INFO",
                              f"Service '{service}' identified but version '{version}' not in local DB",
                              "Verify version against NVD; no automatic match found.")],
                    "source": f,
                })
    return enriched


def severity_rank(sev):
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev.upper(), 0)


def format_for_llm(enriched):
    if not enriched:
        return "No service/version pairs matched the local CVE database."
    enriched_sorted = sorted(
        enriched,
        key=lambda e: max(severity_rank(c[1]) for c in e["cves"]),
        reverse=True,
    )
    lines = ["CVE ENRICHMENT (sorted by severity):", "=" * 60]
    for entry in enriched_sorted:
        lines.append(f"\n[{entry['service'].upper()}] version {entry['version']}")
        lines.append(f"  Source: {entry['source']}")
        for cve_id, sev, name, fix in entry["cves"]:
            lines.append(f"  - {cve_id}  ({sev})  {name}")
            lines.append(f"        Fix: {fix}")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sample = [
            "HTTP 80: status=200, Server=Apache/2.4.49, X-Powered-By=PHP/7.4.3",
            "MySQL 9.6.0 banner on port 3306",
            "OpenSSH_9.0 on port 22",
        ]
    else:
        sample = sys.argv[1:]
    print("[*] Parsing service/version from input strings...")
    enriched = enrich_findings(sample)
    print(format_for_llm(enriched))
    print("\n[*] JSON output:")
    print(json.dumps(enriched, indent=2))
