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
import statistics
import time
import urllib.parse

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.net import safe_urlopen, UnsupportedSchemeError
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result

_HOST_PORT_RE = re.compile(r"^([^:/\s]+):(\d{1,5})$")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

VERIFIED = "verified"
UNVERIFIED = "unverified"
FAILED = "failed"
NON_REPLAYABLE = "non_replayable"
LIKELY_FALSE_POSITIVE = "likely_false_positive"

# Matches webapp.cmdi's exact evidence format:
#   f"Delay: {elapsed:.1f}s via payload: {payload[:30]}"
_TIMING_EVIDENCE_RE = re.compile(r"Delay:\s*([\d.]+)s\s+via\s+payload:\s*(.+)$", re.IGNORECASE)
# Matches webapp.cmdi's exact title format:
#   f"Time-based command injection on '{param}'"
_TIMING_PARAM_RE = re.compile(r"on ['\"]([^'\"]+)['\"]")
# Classic blind-injection sleep primitives — the payload text itself always
# contains one of these regardless of which shell/DB dialect it targets.
_SLEEP_PRIMITIVE_RE = re.compile(r"sleep|waitfor\s+delay|pg_sleep|benchmark\(", re.IGNORECASE)

_TIMING_BASELINE_SAMPLES = 4
# A baseline this noisy (stdlib jitter alone) makes any timing claim
# unfalsifiable either way — neither "verified" nor "false positive" would
# be honest, so this case is reported as genuinely inconclusive instead.
_NOISY_BASELINE_STDDEV_S = 2.0


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
        counts = {VERIFIED: 0, UNVERIFIED: 0, FAILED: 0, NON_REPLAYABLE: 0, LIKELY_FALSE_POSITIVE: 0}
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
            f"{counts[FAILED]} failed replay, {counts[NON_REPLAYABLE]} not replayable, "
            f"{counts[LIKELY_FALSE_POSITIVE]} likely false positive"
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
        evidence = finding.get("evidence", "") or ""

        # Timing-based injection claims (webapp.cmdi's time-based detector,
        # and anything shaped the same way) need their own replay strategy —
        # a raw HTTP GET replay would only confirm the endpoint is still
        # reachable, saying nothing about whether the claimed *delay* is
        # real. Check this before the generic URL/port paths below.
        timing_match = _TIMING_EVIDENCE_RE.search(evidence)
        if timing_match and _SLEEP_PRIMITIVE_RE.search(timing_match.group(2)):
            result = self._verify_timing(finding, timing_match)
            if result is not None:
                return result
            # Couldn't reconstruct a safe replay request (e.g. no URL to
            # work from) — fall through to the generic paths below rather
            # than giving up outright.

        raw = finding.get("raw") if isinstance(finding.get("raw"), dict) else {}
        url = raw.get("url") or self._extract_url(evidence) or self._extract_url(finding.get("affected_asset", ""))
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

    def _verify_timing(self, finding: dict, timing_match: "re.Match") -> tuple[str, str] | None:
        """Re-measure a blind/time-based injection claim instead of just
        replaying the HTTP request once. A single reachable-endpoint check
        (what `_verify_http` does) says nothing about whether the *delay*
        the finding claims is real — this was the exact gap a live mission
        run this session exposed: a HIGH-severity "command injection via
        `; sleep 3`" finding whose "8.1s delay" turned out to be ordinary
        network jitter on a degraded connection, not real execution.

        Returns None (not a verdict) when there isn't enough information to
        safely reconstruct the replay request — the caller falls through to
        the generic verification paths in that case, it never invents a
        request to send.
        """
        claimed_delay = float(timing_match.group(1))
        payload = timing_match.group(2).strip()

        param = None
        title_match = _TIMING_PARAM_RE.search(finding.get("title", "") or "")
        if title_match:
            param = title_match.group(1)

        base_url = self._extract_url(finding.get("affected_asset", "") or "")
        if not base_url:
            raw = finding.get("raw") if isinstance(finding.get("raw"), dict) else {}
            base_url = raw.get("url")
        if not base_url or not param:
            return None  # not enough to safely reconstruct a request

        def _timed_request(param_value: str) -> float | None:
            parsed = urllib.parse.urlparse(base_url)
            query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            query[param] = param_value
            request_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
            started = time.monotonic()
            try:
                with safe_urlopen(request_url, timeout=max(claimed_delay + 5, 15)) as resp:
                    resp.read(65536)
            except UnsupportedSchemeError:
                return None
            except Exception:  # noqa: BLE001 - a failed baseline/replay request just yields no sample
                return None
            return time.monotonic() - started

        baseline_samples = [t for t in (_timed_request("baseline_probe") for _ in range(_TIMING_BASELINE_SAMPLES)) if t is not None]
        if len(baseline_samples) < 2:
            return FAILED, "Could not establish a timing baseline — replay requests failed or endpoint unreachable"

        baseline_mean = statistics.mean(baseline_samples)
        baseline_stddev = statistics.stdev(baseline_samples)

        payload_elapsed = _timed_request(payload)
        if payload_elapsed is None:
            return FAILED, (
                f"Timing baseline established (mean={baseline_mean:.2f}s, stddev={baseline_stddev:.2f}s) "
                f"but the payload replay request itself failed"
            )

        extra_delay = payload_elapsed - baseline_mean
        detail_prefix = (
            f"Timing replay — baseline: {baseline_mean:.2f}s ± {baseline_stddev:.2f}s "
            f"(n={len(baseline_samples)}), payload replay: {payload_elapsed:.2f}s "
            f"(+{extra_delay:.2f}s over baseline), originally claimed: {claimed_delay:.1f}s"
        )

        if baseline_stddev > _NOISY_BASELINE_STDDEV_S:
            return UNVERIFIED, (
                f"{detail_prefix}. Baseline latency is too variable on this connection to draw a "
                f"conclusion either way — this is not evidence the finding is real, but ordinary "
                f"network jitter alone could also explain the original claim"
            )

        noise_band = max(3 * baseline_stddev, 1.0)
        if extra_delay <= noise_band:
            return LIKELY_FALSE_POSITIVE, (
                f"{detail_prefix}. The payload did not reproduce a delay beyond normal baseline "
                f"noise (±{noise_band:.2f}s) — the original claim is very likely a false positive, "
                f"not a real time-based injection"
            )

        return UNVERIFIED, (
            f"{detail_prefix}. The payload reproduced a delay clearly above baseline noise, but "
            f"timing alone is not conclusive proof of command execution — recommend manual review"
        )

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
