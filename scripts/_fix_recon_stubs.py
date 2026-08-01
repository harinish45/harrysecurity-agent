#!/usr/bin/env python3
"""
One-shot patch: fix all stub recon tools that share the same broken HTTP probe.
- Adds ssl.CERT_NONE context so HTTPS doesn't fail on missing certs
- Extracts <title> from HTTP responses
- Reports closed/filtered ports cleanly instead of raw WinError exceptions
"""
from pathlib import Path

RECON_DIR = Path(__file__).parent.parent / "nexus" / "tools" / "reconnaissance"

OLD_IMPORTS = (
    "        import socket\n"
    "        import urllib.request\n"
)

NEW_IMPORTS = (
    "        import re as _re\n"
    "        import socket\n"
    "        import ssl\n"
    "        import urllib.error\n"
    "        import urllib.request\n"
    "\n"
    "        def _extract_title(html):\n"
    "            m = _re.search(r'<title[^>]*>([^<]+)</title>', html, _re.IGNORECASE)\n"
    "            return m.group(1).strip() if m else ''\n"
    "\n"
    "        ssl_ctx = ssl.create_default_context()\n"
    "        ssl_ctx.check_hostname = False\n"
    "        ssl_ctx.verify_mode = ssl.CERT_NONE\n"
)

OLD_PROBE = (
    "                resp = urllib.request.urlopen(req, timeout=5)\n"
    "                findings.append(f\"HTTP {scheme}://{target}: status={resp.status},"
    " Server={resp.headers.get('Server', 'unknown')}\")\n"
    "            except Exception as e:\n"
    "                findings.append(f\"HTTP {scheme}://{target}: {str(e)[:80]}\")\n"
)

NEW_PROBE = (
    "                resp = urllib.request.urlopen(req, timeout=6, context=ssl_ctx)\n"
    "                server = resp.headers.get('Server', 'unknown')\n"
    "                body = resp.read(4096).decode('utf-8', errors='replace')\n"
    "                title = _extract_title(body)\n"
    "                title_note = f\", Title='{title}'\" if title else ''\n"
    "                findings.append(\n"
    "                    f\"{scheme.upper()} {url}: status={resp.status},\"\n"
    "                    f\" Server={server}{title_note}\"\n"
    "                )\n"
    "            except urllib.error.HTTPError as e:\n"
    "                findings.append(f\"{scheme.upper()} {url}: HTTP {e.code} {e.reason}\")\n"
    "            except OSError:\n"
    "                findings.append(f\"{scheme.upper()} {url}: port not reachable (closed or filtered)\")\n"
    "            except Exception as e:\n"
    "                findings.append(f\"{scheme.upper()} {url}: {str(e)[:120]}\")\n"
)

TARGETS = [
    "censys_search.py",
    "cert_transparency.py",
    "email_harvest.py",
    "github_recon.py",
    "google_dorking.py",
    "shodan_search.py",
    "social_osint.py",
    "whois_lookup.py",
]

fixed = 0
for fname in TARGETS:
    fpath = RECON_DIR / fname
    if not fpath.exists():
        print(f"  MISSING : {fname}")
        continue
    text = fpath.read_text(encoding="utf-8")
    updated = text.replace(OLD_IMPORTS, NEW_IMPORTS).replace(OLD_PROBE, NEW_PROBE)
    if updated != text:
        fpath.write_text(updated, encoding="utf-8")
        print(f"  FIXED   : {fname}")
        fixed += 1
    else:
        print(f"  SKIPPED : {fname} (pattern not matched — may already be fixed)")

print(f"\nDone. {fixed}/{len(TARGETS)} files patched.")
