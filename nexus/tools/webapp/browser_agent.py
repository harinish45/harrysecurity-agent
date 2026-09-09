#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.browser_agent
Domain: webapp
Real headless-browser page load and DOM inspection (Playwright), with an
honest unavailable-status fallback when Playwright isn't installed.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no browser involved whatsoever —
despite the tool's entire purpose being browser-rendered analysis).
Now: a real check for the `playwright` package; if present, a real
minimal headless page load plus DOM checks (page title, console errors,
inline <script> presence, mixed-content resources). If Playwright is not
installed in this environment, the tool honestly reports
STATUS_UNAVAILABLE with the real reason instead of faking a result.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import importlib.util
import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Browser Agent)"


def _playwright_available() -> bool:
    return importlib.util.find_spec("playwright") is not None


def _run_with_playwright(url: str, timeout: int) -> dict:
    """Real minimal headless page load + DOM check via Playwright sync API."""
    from playwright.sync_api import sync_playwright  # type: ignore

    console_errors: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(user_agent=USER_AGENT)
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.goto(url, timeout=timeout * 1000, wait_until="load")
            title = page.title()
            script_count = page.eval_on_selector_all("script", "els => els.length")
            forms_count = page.eval_on_selector_all("form", "els => els.length")
            mixed_content = []
            if url.startswith("https://"):
                srcs = page.eval_on_selector_all("img[src], script[src], link[href]", "els => els.map(e => e.src || e.href)")
                mixed_content = [s for s in srcs if s and s.startswith("http://")]
            return {
                "loaded": True, "title": title, "script_count": script_count,
                "forms_count": forms_count, "console_errors": console_errors[:20],
                "mixed_content": mixed_content[:20],
            }
        finally:
            browser.close()


def _fallback_probe(url: str, timeout: int) -> dict:
    """Non-browser fallback status probe, used only to confirm target is reachable
    when reporting the unavailable status (does not substitute for a real render)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        resp.read(1024)
        return {"status": resp.status}
    except urllib.error.HTTPError as e:
        return {"status": e.code}
    except Exception as e:
        return {"status": 0, "error": str(e)[:100]}


def run(target: str, timeout: int = 15, **kwargs: Any) -> dict:
    """Perform a real headless-browser page load and DOM inspection, if Playwright
    is installed; otherwise honestly report the tool as unavailable.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Page-load timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.browser_agent", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"

    if not _playwright_available():
        probe = _fallback_probe(url, timeout=min(timeout, 10))
        return tool_result(
            "webapp.browser_agent", target,
            status=STATUS_UNAVAILABLE,
            summary="Playwright is not installed in this environment — headless-browser rendering/DOM inspection cannot run.",
            error="ModuleNotFoundError: playwright is not installed (pip install playwright && playwright install chromium)",
            metadata={"playwright_installed": False, "target_reachable_status": probe.get("status")},
        )

    try:
        render = _run_with_playwright(url, timeout)
    except Exception as e:
        return tool_result("webapp.browser_agent", target, status=STATUS_FAILED, error=f"Browser render failed: {str(e)[:200]}")

    findings: list[Finding] = []
    if render["console_errors"]:
        findings.append(Finding(
            title=f"{len(render['console_errors'])} browser console error(s) on page load",
            severity="low",
            confidence="high",
            affected_asset=url,
            evidence="; ".join(render["console_errors"][:5]),
            remediation="Review client-side JavaScript errors; some may indicate broken security controls (CSP violations, failed auth checks, etc.).",
            tool="webapp.browser_agent",
            references=[],
        ))
    if render["mixed_content"]:
        findings.append(Finding(
            title=f"Mixed content: {len(render['mixed_content'])} resource(s) loaded over HTTP on an HTTPS page",
            severity="medium",
            confidence="high",
            affected_asset=url,
            evidence="; ".join(render["mixed_content"][:5]),
            remediation="Serve all page resources over HTTPS to avoid mixed-content downgrade/MITM risk.",
            tool="webapp.browser_agent",
            references=["CWE-319"],
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Rendered {url} — title='{render['title']}', {render['script_count']} script(s), {render['forms_count']} form(s), {len(render['console_errors'])} console error(s)"

    return tool_result(
        "webapp.browser_agent", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"playwright_installed": True, **render},
    )


tool_registry.register("webapp.browser_agent", run, metadata={
    "name": "webapp.browser_agent",
    "domain": "webapp",
    "status": "completed",
    "description": "Real headless-browser (Playwright) page load and DOM/console/mixed-content inspection; honestly reports unavailable if Playwright isn't installed",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Page-load timeout in seconds (default: 15)",
    },
})
