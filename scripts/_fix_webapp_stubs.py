#!/usr/bin/env python3
"""
Bulk-patch all webapp stub tools that dump raw HTML body.
Replaces: findings.append(f"Response body (first 500 chars): {body[:500]}")
With:      title extraction + security header findings
Also replaces the old HTTP status line format with the cleaner one.
"""
from pathlib import Path
import re

WEBAPP_DIR = Path(__file__).parent.parent / "nexus" / "tools" / "webapp"

# Pattern 1: old status line (without title)
OLD_STATUS = (
    'findings.append(f"HTTP {resp.status}: Server={resp.headers.get(\'Server\', \'unknown\')},'
    ' X-Powered-By={resp.headers.get(\'X-Powered-By\', \'\')}")\n'
    '            body = resp.read(4096).decode(\'utf-8\', errors=\'replace\')\n'
    '            findings.append(f"Response body (first 500 chars): {body[:500]}")'
)

NEW_STATUS = (
    "import re as _re\n"
    "            def _title(h):\n"
    "                m = _re.search(r'<title[^>]*>([^<]+)</title>', h, _re.IGNORECASE)\n"
    "                return m.group(1).strip() if m else ''\n"
    "            server = resp.headers.get('Server', 'unknown')\n"
    "            powered_by = resp.headers.get('X-Powered-By', '')\n"
    "            csp = resp.headers.get('Content-Security-Policy', 'missing')\n"
    "            hsts = resp.headers.get('Strict-Transport-Security', 'missing')\n"
    "            x_frame = resp.headers.get('X-Frame-Options', 'missing')\n"
    "            body = resp.read(4096).decode('utf-8', errors='replace')\n"
    "            title = _title(body)\n"
    "            findings.append(\n"
    "                f\"HTTP {resp.status} {url}: Server={server}\"\n"
    "                + (f\", X-Powered-By={powered_by}\" if powered_by else \"\")\n"
    "                + (f\", Title='{title}'\" if title else \"\")\n"
    "            )\n"
    "            findings.append(f\"Security headers — CSP={csp}, HSTS={hsts}, X-Frame-Options={x_frame}\")\n"
    "            if csp == 'missing':\n"
    "                findings.append('WARN: Content-Security-Policy header absent')\n"
    "            if hsts == 'missing':\n"
    "                findings.append('WARN: Strict-Transport-Security header absent')\n"
    "            if x_frame == 'missing':\n"
    "                findings.append('WARN: X-Frame-Options header absent (potential clickjacking)')"
)

TARGETS = [
    "auth_test.py", "authorization_test.py", "browser_agent.py",
    "business_logic.py", "csrf.py", "file_upload.py", "graphql.py",
    "idor.py", "jwt_analysis.py", "param_discovery.py", "rate_limit.py",
    "rest_api_testing.py", "rfi.py", "scanner.py", "session_mgmt.py",
    "traversal.py", "waf_detect.py", "xxe.py",
]

fixed = 0
for fname in TARGETS:
    fpath = WEBAPP_DIR / fname
    if not fpath.exists():
        print(f"  MISSING : {fname}")
        continue
    text = fpath.read_text(encoding="utf-8")

    # Replace old raw body dump line pattern using regex for flexibility
    updated = re.sub(
        r"findings\.append\(f\"HTTP \{resp\.status\}: Server=\{resp\.headers\.get\('Server', 'unknown'\)\},"
        r" X-Powered-By=\{resp\.headers\.get\('X-Powered-By', ''\)\}\"\)\n"
        r"            body = resp\.read\(4096\)\.decode\('utf-8', errors='replace'\)\n"
        r"            findings\.append\(f\"Response body \(first 500 chars\): \{body\[:500\]\}\"\)",
        NEW_STATUS,
        text,
    )

    if updated != text:
        fpath.write_text(updated, encoding="utf-8")
        print(f"  FIXED   : {fname}")
        fixed += 1
    else:
        print(f"  SKIPPED : {fname} (pattern not matched)")

print(f"\nDone. {fixed}/{len(TARGETS)} files patched.")
