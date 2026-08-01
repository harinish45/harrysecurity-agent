#!/usr/bin/env python3
"""
NEXUS-STRIKE — Interactive Terminal Driver
==========================================
Shows an ASCII banner and 4-option menu, then runs the 11-phase scanner.

Usage:
    python scripts/nexus_scan.py
    python scripts/nexus_scan.py --target 127.0.0.1
    python scripts/nexus_scan.py --non-interactive --target scanme.nmap.org
"""
from __future__ import annotations

import os
import sys
import time
import json
import argparse
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from nexus.foundation.logging import logger
from live_agent import run_assessment  # noqa: E402


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = r"""
   _   _  ___  __  __  _____  _____  _   _   _      _____
  | \ | || __||  \/  ||_   _|| ____|| \ | | | |    / ____|
  |  \| || _| | |\/| |  | | |  _|  |  \| | | |   | (___
  | |\  || |__| |  | |  | | | |___ | |\  | | |___ \___ \
  |_| \_||___||_|  |_|  |_| |_____||_| \_| |_____|____ /

       [ Autonomous AI Cybersecurity Assessment ]
"""

MENU = """
  Where do you want to scan?

  [1] Localhost                 (your own machine)
  [2] Nmap test target          (legal public test)
  [3] Acunetix test site        (legal public test)
  [4] Custom URL or IP          (you paste it)

  Pick one (1-4): """


# ---------------------------------------------------------------------------
# Menu logic
# ---------------------------------------------------------------------------
PRESET_TARGETS = {
    "1": ("127.0.0.1", "localhost"),
    "2": ("scanme.nmap.org", "scanme.nmap.org"),
    "3": ("testphp.vulnweb.com", "testphp.vulnweb.com"),
}


def show_banner() -> None:
    print(BANNER)


def prompt_target() -> tuple[str, str]:
    while True:
        try:
            choice = input(MENU).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Exiting.")
            sys.exit(0)

        if choice in PRESET_TARGETS:
            return PRESET_TARGETS[choice]
        if choice == "4":
            try:
                custom = input("Enter URL or IP: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Exiting.")
                sys.exit(0)
            if not custom:
                print("[!] Please enter a valid URL or IP.")
                continue
            return custom, custom
        print(f"[!] Invalid choice '{choice}'. Enter 1-4.")


# ---------------------------------------------------------------------------
# Report saving
# ---------------------------------------------------------------------------
REPORTS_DIR = Path(_PROJECT_ROOT) / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


def save_results(result: dict) -> Path:
    target_slug = result["_meta"]["target"].replace("/", "_").replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target_slug}_{ts}.json"
    path = REPORTS_DIR / filename
    path.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------
def run_driver(target: str | None = None, host: str | None = None, non_interactive: bool = False) -> dict:
    show_banner()

    if target:
        target_ip = target
        target_host = host or target
    elif non_interactive:
        print("[!] --target is required in --non-interactive mode.")
        sys.exit(1)
    else:
        target_ip, target_host = prompt_target()

    print(f"\n[*] Target : {target_host} ({target_ip})")
    print("[*] Starting 11-phase assessment...\n")

    t0 = time.time()
    result = run_assessment(target_ip=target_ip, target_host=target_host)
    elapsed = round(time.time() - t0, 1)

    path = save_results(result)
    print(f"\n[*] Raw results saved: {path}")
    print(f"[*] Elapsed: {elapsed}s")
    print("\nNext steps:")
    print(f"  1. Review JSON:  {path}")
    print(f"  2. Generate PDF: python scripts/nexus_report.py {path}")
    print(f"  3. View reports: python scripts/serve_reports.py\n")

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="NEXUS-STRIKE Interactive Terminal Driver")
    ap.add_argument("--target", "-t", default=None, help="Target IP or hostname")
    ap.add_argument("--host", "-H", default=None, help="Target hostname for DNS")
    ap.add_argument("--non-interactive", "-n", action="store_true", help="Skip menu, use --target")
    args = ap.parse_args()
    run_driver(target=args.target, host=args.host, non_interactive=args.non_interactive)


if __name__ == "__main__":
    main()
