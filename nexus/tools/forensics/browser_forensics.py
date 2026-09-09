#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.browser_forensics
Domain: forensics
Real browser history extraction: reads a local SQLite database file via the
stdlib `sqlite3` module and, if its schema matches Chrome/Chromium's `urls`
table or Firefox's `moz_places` table, lists real visited-URL history from
it. Honest-degrades when the file isn't a SQLite database, or is one but
doesn't match either known browser-history schema.
"""
from __future__ import annotations
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Any
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

MAX_ROWS = 200
# Chrome/Chromium timestamps are microseconds since 1601-01-01 (Windows FILETIME epoch).
CHROME_EPOCH_OFFSET_US = 11644473600 * 1_000_000


def _chrome_time_to_iso(value: int) -> str:
    try:
        unix_us = value - CHROME_EPOCH_OFFSET_US
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return ""


def _firefox_time_to_iso(value: int) -> str:
    try:
        return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return ""


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return {row[1] for row in cur.fetchall()}
    except sqlite3.Error:
        return set()


def run(target: str, **kwargs: Any) -> dict:
    """Extract real browser history from a local Chrome/Firefox SQLite database file."""
    if not target or not os.path.isfile(target):
        return tool_result(
            "forensics.browser_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a readable local file — browser forensics requires a local "
                    "'History' (Chrome/Chromium) or 'places.sqlite' (Firefox) database file.",
            error="target is not a local file",
        )

    # SQLite may hold a write lock on a live browser profile's file; work off
    # a read-only copy so this never blocks on / corrupts a real profile.
    tmp_dir = tempfile.mkdtemp(prefix="nexus_browser_forensics_")
    tmp_copy = os.path.join(tmp_dir, "copy.sqlite")
    try:
        shutil.copy2(target, tmp_copy)
        conn = sqlite3.connect(f"file:{tmp_copy}?mode=ro", uri=True)
    except (OSError, sqlite3.Error) as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return tool_result("forensics.browser_forensics", target, status=STATUS_FAILED, error=str(e))

    try:
        try:
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        except sqlite3.DatabaseError as e:
            return tool_result(
                "forensics.browser_forensics", target,
                status=STATUS_UNAVAILABLE,
                summary=f"File is not a valid SQLite database: {e}",
                error=str(e),
            )

        history: list[dict] = []
        browser = None

        if "urls" in tables and {"url", "title", "visit_count"} <= _table_columns(conn, "urls"):
            browser = "chrome"
            rows = conn.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls "
                "ORDER BY last_visit_time DESC LIMIT ?", (MAX_ROWS,)
            ).fetchall()
            for url, title, visit_count, last_visit_time in rows:
                history.append({
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_time": _chrome_time_to_iso(last_visit_time) if last_visit_time else "",
                })
        elif "moz_places" in tables and {"url", "title", "visit_count"} <= _table_columns(conn, "moz_places"):
            browser = "firefox"
            rows = conn.execute(
                "SELECT url, title, visit_count, last_visit_date FROM moz_places "
                "ORDER BY last_visit_date DESC LIMIT ?", (MAX_ROWS,)
            ).fetchall()
            for url, title, visit_count, last_visit_date in rows:
                history.append({
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_time": _firefox_time_to_iso(last_visit_date) if last_visit_date else "",
                })
        else:
            return tool_result(
                "forensics.browser_forensics", target,
                status=STATUS_UNAVAILABLE,
                summary="SQLite file does not match a known Chrome ('urls' table) or Firefox "
                        "('moz_places' table) browser-history schema.",
                error="unrecognized schema",
                metadata={"tables_found": sorted(tables)},
            )

        findings = [Finding(
            title=f"Browser history extracted ({browser})",
            severity="info",
            confidence="certain",
            affected_asset=target,
            evidence=f"Extracted {len(history)} history entr{'y' if len(history) == 1 else 'ies'} "
                     f"from the '{'urls' if browser == 'chrome' else 'moz_places'}' table.",
            remediation="Review URLs for indicators of compromise, data exfiltration, or policy violations.",
            tool="forensics.browser_forensics",
        )] if history else []

        status = STATUS_COMPLETED if history else STATUS_NO_FINDINGS
        return tool_result(
            "forensics.browser_forensics", target,
            status=status,
            findings=findings,
            summary=f"Extracted {len(history)} {browser} history entries.",
            metadata={"browser": browser, "history": history},
        )
    finally:
        conn.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)


tool_registry.register("forensics.browser_forensics", run, metadata={
    "name": "forensics.browser_forensics",
    "domain": "forensics",
    "status": "completed",
    "description": "Extracts real visited-URL history from a local Chrome ('urls' table) or Firefox ('moz_places' table) SQLite history database",
    "parameters": {"target": "Path to a local browser history SQLite file (Chrome 'History' or Firefox 'places.sqlite')"},
})
