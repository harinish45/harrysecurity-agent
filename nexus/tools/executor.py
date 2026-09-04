"""The single, guarded entrypoint for tool execution."""
from __future__ import annotations

import concurrent.futures
import json
import time
from typing import Any

from nexus.foundation.config import config
from nexus.foundation.guardrails import (
    AuditGuard,
    EscalationGuard,
    InputGuard,
    LegalGuard,
    OutputGuard,
    RateGuard,
    ScopeGuard,
)
from nexus.foundation.schema import (
    ALL_STATUSES,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_REQUIRES_HARDWARE,
    STATUS_UNAVAILABLE,
    Finding,
    tool_result,
)
from nexus.tools.registry import tool_registry


class ToolExecutionError(RuntimeError):
    """Raised when a tool does not honour the framework result contract."""


# Shared across ToolExecutor instances so nexus_max_concurrent_tools is a
# real global cap, not per-instance (a fresh unbounded pool per executor
# would defeat the point of the setting).
_EXECUTOR_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=max(1, int(getattr(config, "nexus_max_concurrent_tools", 5))),
    thread_name_prefix="nexus-tool",
)


class ToolExecutor:
    """Validate, audit, and execute registered tools consistently.

    Enforces:
    - Truthful statuses (no fake "completed" on failure)
    - Unified finding schema
    - Engagement requirement for non-local targets
    - All guardrails
    """

    def __init__(self, require_engagement: bool = False) -> None:
        self._require_engagement = require_engagement

    def run(
        self,
        tool_name: str,
        target: str,
        *,
        engagement: dict[str, Any] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if not isinstance(target, str) or not target.strip():
            raise ToolExecutionError("A non-empty string target is required")

        # ── Engagement check for non-local targets ──────────────────────
        is_local = target in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
        if not is_local and self._require_engagement and not engagement:
            return tool_result(
                tool_name, target,
                status=STATUS_OUT_OF_SCOPE,
                summary="Non-local target requires an engagement record. Use `nexus engage` first.",
            )

        # ── Guardrails must run before any network action ───────────────
        try:
            InputGuard.validate(target, context={"tool": tool_name})
            ScopeGuard.validate(target)
            LegalGuard.validate(target=target)
            EscalationGuard.validate(tool_name=tool_name, action="execute")
            RateGuard.validate(target=target)
            AuditGuard.validate(action=tool_name, target=target)
        except Exception as exc:
            return tool_result(
                tool_name, target,
                status=STATUS_FAILED,
                error=f"Guardrail blocked: {exc}",
            )

        # ── Execute the tool, with a real timeout ────────────────────────
        # nexus_tool_timeout used to be measured (time.monotonic()) but never
        # enforced — a hung tool call would block the caller indefinitely.
        # A thread-pool future gives the caller a bounded wait; note this
        # can't force-kill a stuck native/C-extension call inside the
        # worker thread (Python has no safe thread-kill), so a genuinely
        # wedged tool still leaks a background thread — the fix for that
        # class of tool is to shell out via run_subprocess() (nexus/tools/
        # sandbox.py), which *can* be killed on timeout. This still turns
        # "the dashboard hangs forever" into "the caller gets a prompt,
        # truthful failure," which is the actual problem being solved here.
        tool = tool_registry.get(tool_name)
        started = time.monotonic()
        timeout_s = timeout if timeout is not None else getattr(config, "nexus_tool_timeout", 300)
        future = _EXECUTOR_POOL.submit(tool, target=target, **kwargs)
        try:
            result = future.result(timeout=timeout_s)
        except concurrent.futures.TimeoutError:
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            AuditGuard.validate(action=f"{tool_name}.timeout", target=target, timeout_s=timeout_s)
            return tool_result(
                tool_name, target,
                status=STATUS_FAILED,
                error=f"Tool exceeded timeout of {timeout_s}s",
                metadata={"execution_ms": elapsed_ms, "timed_out": True},
            )
        except Exception as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            return tool_result(
                tool_name, target,
                status=STATUS_FAILED,
                error=str(exc),
                metadata={"execution_ms": elapsed_ms},
            )
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)

        # ── Validate result contract ────────────────────────────────────
        if not isinstance(result, dict):
            raise ToolExecutionError(
                f"{tool_name} returned {type(result).__name__}, not a dictionary"
            )

        # Normalise status — tools may still return old-style strings
        raw_status = result.get("status", STATUS_COMPLETED)
        if raw_status not in ALL_STATUSES:
            raw_status = STATUS_FAILED

        # Normalise findings to the canonical schema
        raw_findings = result.get("findings", [])
        if not isinstance(raw_findings, list):
            raw_findings = []

        normalised: list[dict[str, Any]] = []
        for f in raw_findings:
            if isinstance(f, dict):
                # Already a dict — ensure it has all Finding fields
                normalised.append(Finding(**f).to_dict())
            else:
                normalised.append(
                    Finding(
                        title=str(f)[:120],
                        severity="info",
                        tool=tool_name,
                        affected_asset=target,
                    ).to_dict()
                )

        # Build the canonical result
        canonical = tool_result(
            tool_name,
            target,
            status=raw_status,
            findings=[Finding(**f) for f in normalised],
            summary=result.get("summary", ""),
            error=result.get("error", ""),
            metadata={
                "execution_ms": elapsed_ms,
                **(result.get("metadata") or {}),
            },
        )

        # Validate output for secret leakage
        OutputGuard.validate(
            json.dumps(canonical, default=str),
            context={"tool": tool_name},
        )
        return canonical