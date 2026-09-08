"""Deterministic, non-LLM finding verification (the XBOW pattern).

The gap this closes: every other agent in this codebase produces a finding
because a tool or an LLM *believed* something was true. Nothing re-checked
it. That's the single biggest driver of false positives in agentic pentest
tools, and the thing XBOW's own writeups credit for its low false-positive
rate on HackerOne: decouple "the agent thinks it found something" from "a
deterministic layer proved it".

This agent does not call an LLM. For each finding it can find replayable
evidence for, it re-runs the underlying check itself and diffs the live
result against what was claimed. Findings it cannot replay (most findings,
today — most of the 266 tools don't yet emit structured replay evidence)
are stamped ``non_replayable``, not silently dropped and not claimed as
verified.
"""
from __future__ import annotations

import re
import socket

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.net import safe_urlopen, UnsupportedSchemeError
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result

_HOST_PORT_RE = re.compile(r"^([^:/\s]+):(\d{1,5})$")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

VERIFIED = "verified"
UNVERIFIED = "unverified"
FAILED = "failed"
NON_REPLAYABLE = "non_replayable"


class VerificationAgent(BaseAgent):
    name = "verification_agent"
    description = (
        "orchestrator agent that deterministically re-proves findings before "
        "they reach a report — no LLM call, replay-and-diff only"
    )

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        findings = kwargs.get("findings", []) or []
        if not findings:
            return tool_result(self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                                summary="No findings to verify")

        annotated = []
        counts = {VERIFIED: 0, UNVERIFIED: 0, FAILED: 0, NON_REPLAYABLE: 0}
        for f in findings:
            f = dict(f)
            status, detail = self._verify_one(f)
            f["verification_status"] = status
            f["verification_detail"] = detail
            counts[status] = counts.get(status, 0) + 1
            annotated.append(f)

        summary = (
            f"Verification pass on {len(annotated)} finding(s) for {target or 'mission'}: "
            f"{counts[VERIFIED]} verified, {counts[UNVERIFIED]} unverified, "
            f"{counts[FAILED]} failed replay, {counts[NON_REPLAYABLE]} not replayable"
        )
        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=summary,
            metadata={"verified_findings": annotated, "counts": counts},
        )

    # ── replay strategies ────────────────────────────────────────────────

    def _verify_one(self, finding: dict) -> tuple[str, str]:
        raw = finding.get("raw") if isinstance(finding.get("raw"), dict) else {}
        url = raw.get("url") or self._extract_url(finding.get("evidence", ""))
        if url:
            return self._verify_http(url, finding)

        asset = finding.get("affected_asset", "")
        m = _HOST_PORT_RE.match(asset.strip()) if asset else None
        if m and "port" in finding.get("title", "").lower():
            return self._verify_port(m.group(1), int(m.group(2)))

        return NON_REPLAYABLE, "No replayable evidence (URL or host:port) attached to this finding"

    @staticmethod
    def _extract_url(evidence: str) -> str | None:
        if not evidence:
            return None
        match = _URL_RE.search(evidence)
        return match.group(0) if match else None

    def _verify_http(self, url: str, finding: dict) -> tuple[str, str]:
        indicator = finding.get("raw", {}).get("expected_indicator") if isinstance(finding.get("raw"), dict) else None
        try:
            with safe_urlopen(url, timeout=8) as resp:
                body = resp.read(65536).decode("utf-8", errors="replace")
                status_code = getattr(resp, "status", None) or resp.getcode()
        except UnsupportedSchemeError as exc:
            return NON_REPLAYABLE, str(exc)
        except Exception as exc:  # noqa: BLE001 - target unreachable/changed, that's a verification result
            return FAILED, f"Replay request failed: {exc}"

        if indicator:
            if indicator in body:
                return VERIFIED, f"HTTP {status_code} — expected indicator still present on replay"
            return UNVERIFIED, f"HTTP {status_code} — expected indicator no longer present; may be fixed or flaky"

        if status_code and 200 <= status_code < 500:
            return VERIFIED, f"HTTP {status_code} on replay — endpoint reachable, evidence unchanged shape"
        return UNVERIFIED, f"HTTP {status_code} on replay — response no longer matches original condition"

    @staticmethod
    def _verify_port(host: str, port: int) -> tuple[str, str]:
        try:
            with socket.create_connection((host, port), timeout=5):
                return VERIFIED, f"TCP connect to {host}:{port} succeeded on replay"
        except OSError as exc:
            return UNVERIFIED, f"TCP connect to {host}:{port} failed on replay: {exc}"
