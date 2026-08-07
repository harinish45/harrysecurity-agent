#!/usr/bin/env python3
"""
NEXUS-STRIKE — CVE Enrichment Extension (v2)
Takes raw recon findings (service + version) and matches them against a
local CVE knowledge base. Adds severity, CVE ID, and remediation hints
so the LLM phases have something concrete to work with.

v2: adds fallback matches for unknown versions and port-only detections.

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
    # =====================================================================
    # Issue 5: Generic fallback matches for unknown versions / port-only detections
    # =====================================================================
    "generic": [
        {"version_prefix": "", "cves": [
            # Open database ports — always flagged regardless of version
            ("PORT-3306", "HIGH", "MySQL port 3306 exposed",
             "Bind to 127.0.0.1. Enforce strong authentication. Disable default accounts. Apply patches."),
            ("PORT-5432", "HIGH", "PostgreSQL port 5432 exposed",
             "Bind to 127.0.0.1. Require TLS for remote connections. Apply patches."),
            ("PORT-6379", "HIGH", "Redis port 6379 exposed",
             "Bind to 127.0.0.1. Enable AUTH password. Disable dangerous commands. Apply patches."),
            ("PORT-9200", "HIGH", "Elasticsearch port 9200 exposed",
             "Bind to 127.0.0.1. Enable X-Pack security. Apply patches."),
            ("PORT-27017", "HIGH", "MongoDB port 27017 exposed",
             "Bind to 127.0.0.1. Enable authentication. Disable --noauth. Apply patches."),
            ("PORT-1433", "HIGH", "MSSQL port 1433 exposed",
             "Bind to private interface. Enforce strong SA password. Disable xp_cmdshell."),
            # SMB / NetBIOS
            ("PORT-445", "CRITICAL", "SMB port 445 exposed",
             "Block at perimeter. Disable SMBv1. Enforce SMB signing. Patch for EternalBlue (MS17-010)."),
            ("PORT-139", "CRITICAL", "NetBIOS port 139 exposed",
             "Block at perimeter. Disable NetBIOS over TCP/IP if not required."),
            # RDP
            ("PORT-3389", "HIGH", "RDP port 3389 exposed",
             "Restrict source IPs. Enable NLA. Enforce MFA. Patch for BlueKeep (CVE-2019-0708)."),
            # Telnet
            ("PORT-23", "HIGH", "Telnet port 23 exposed",
             "Telnet transmits all data in plaintext. Replace with SSH."),
            # FTP
            ("PORT-21", "HIGH", "FTP port 21 exposed",
             "FTP transmits credentials in plaintext. Replace with SFTP or FTPS. Disable anonymous."),
            # SSH
            ("PORT-22", "MEDIUM", "SSH port 22 exposed",
             "Verify OpenSSH version. Patch for regreSSHion (CVE-2024-6387). Enforce key-based auth."),
            # HTTP / generic web
            ("PORT-80", "MEDIUM", "HTTP port 80 exposed without TLS",
             "Redirect to HTTPS. Add security headers. Review for OWASP Top 10."),
            ("PORT-443", "LOW", "HTTPS port 443 exposed",
             "Verify TLS 1.2+ with strong ciphers. Add HSTS. Review for OWASP Top 10."),
            # Header hygiene (detected from banners)
            ("MISSING-HSTS", "MEDIUM", "HTTP Strict-Transport-Security header missing",
             "Add HSTS header with min-age of at least 31536000."),
            ("MISSING-CSP", "MEDIUM", "Content-Security-Policy header missing",
             "Add CSP header to mitigate XSS and data injection."),
            ("MISSING-XFO", "LOW", "X-Frame-Options header missing",
             "Add X-Frame-Options: DENY or SAMEORIGIN to mitigate clickjacking."),
            ("VERSION-DISCLOSURE", "LOW", "Server/X-Powered-By version disclosed",
             "Suppress version information in HTTP response headers."),
            # DNS
            ("DNS-ZONE-XFER", "HIGH", "DNS zone transfer may be open",
             "Restrict zone transfers to authorized secondary nameservers."),
            ("NO-DNSSEC", "MEDIUM", "DNSSEC not validated",
             "Enable DNSSEC validation on recursive resolvers."),
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

# Issue 5: Port-based fallback patterns
PORT_PATTERNS = [
    (r"\b(3306)\b", "mysql", "3306"),
    (r"\b(5432)\b", "postgres", "5432"),
    (r"\b(6379)\b", "redis", "6379"),
    (r"\b(9200)\b", "elasticsearch", "9200"),
    (r"\b(27017)\b", "mongodb", "27017"),
    (r"\b(1433)\b", "mssql", "1433"),
    (r"\b(445)\b", "smb", "445"),
    (r"\b(139)\b", "netbios", "139"),
    (r"\b(3389)\b", "rdp", "3389"),
    (r"\b(23)\b", "telnet", "23"),
    (r"\b(21)\b", "ftp", "21"),
    (r"\b(22)\b", "ssh", "22"),
]

# Issue 5: Header hygiene patterns
HEADER_PATTERNS = [
    (r"(?i)missing.*HSTS|no.*strict-transport", "missing-hsts"),
    (r"(?i)missing.*CSP|no.*content-security", "missing-csp"),
    (r"(?i)missing.*X-Frame|x-frame.*missing", "missing-xfo"),
    (r"(?i)server:\s*\w+/[\d.]+|x-powered-by", "version-disclosure"),
]


def parse_services(text):
    hits = []
    for pattern, key in SERVICE_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            hits.append((key, m.group(1)))
    return hits


def parse_ports(text):
    """Issue 5: detect port numbers even without version info."""
    hits = []
    seen = set()
    for pattern, svc, port in PORT_PATTERNS:
        for m in re.finditer(pattern, text):
            key = (f"port-{svc}", port)
            if key not in seen:
                seen.add(key)
                hits.append(key)
    return hits


def parse_header_issues(text):
    """Issue 5: detect HTTP header hygiene issues."""
    hits = []
    seen = set()
    for pattern, key in HEADER_PATTERNS:
        if re.search(pattern, text):
            if key not in seen:
                seen.add(key)
                hits.append(("generic", key))
    return hits


def lookup_cves(service, version):
    entries = CVE_DB.get(service.lower(), [])
    hits = []
    for entry in entries:
        if version.startswith(entry["version_prefix"]):
            hits.extend(entry["cves"])
    return hits


def lookup_generic_cves(tag):
    """Issue 5: lookup generic fallback CVEs by tag (PORT-22, MISSING-HSTS, etc)."""
    entries = CVE_DB.get("generic", [])
    hits = []
    for entry in entries:
        for cve_id, sev, name, fix in entry["cves"]:
            if cve_id == tag.upper() or cve_id.lower() == tag.lower():
                hits.append((cve_id, sev, name, fix))
    return hits


def enrich_findings(findings, llm_router=None):
    enriched = []
    seen = set()
    for f in findings or []:
        if not isinstance(f, str):
            continue

        # Standard service/version matches
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

        # Issue 5: port-based fallback matches
        for service, port in parse_ports(f):
            tag = f"PORT-{port}"
            key = ("generic", tag)
            if key in seen:
                continue
            seen.add(key)
            cves = lookup_generic_cves(tag)
            if cves:
                enriched.append({
                    "service": service, "version": f"port-{port}",
                    "cves": cves, "source": f,
                })

        # Issue 5: header hygiene fallback
        for service, tag in parse_header_issues(f):
            key = ("generic", tag)
            if key in seen:
                continue
            seen.add(key)
            cves = lookup_generic_cves(tag)
            if cves:
                enriched.append({
                    "service": service, "version": tag,
                    "cves": cves, "source": f,
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
            "Open port 445 on target (SMB)",
            "Open port 3389 (RDP)",
        ]
    else:
        sample = sys.argv[1:]
    print("[*] Parsing service/version from input strings...")
    enriched = enrich_findings(sample)
    print(format_for_llm(enriched))
    print("\n[*] JSON output:")
    print(json.dumps(enriched, indent=2))
