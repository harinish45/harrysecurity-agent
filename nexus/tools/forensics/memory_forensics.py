#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.memory_forensics
Domain: forensics
Real memory-dump triage: if the optional `volatility3` framework is
installed, attempts a minimal windows.pslist (or linux.pslist) plugin run
against a local memory-dump file to list real running processes as of
capture time — using volatility3's own documented context/automagic/plugin
construction API. Honest-degrades (matching reverse_engineering.disassemble's
capstone-missing pattern) when volatility3 isn't installed — it is not, in
this environment; see requirements.txt — or when target isn't a plausible
local memory-dump file.
"""
from __future__ import annotations
import os
from typing import Any
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

# A real memory dump is at least a few MB; guards against treating an
# arbitrary small file as a plausible dump.
MIN_DUMP_SIZE = 1024 * 1024
MAX_PROCESSES = 100


def run(target: str, **kwargs: Any) -> dict:
    """Attempt a minimal Volatility3 pslist plugin run against a local memory-dump file."""
    if not target or not os.path.isfile(target):
        return tool_result(
            "forensics.memory_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a readable local file — memory forensics requires a local "
                    "memory-dump file path, not a network target.",
            error="target is not a local file",
        )

    try:
        size = os.path.getsize(target)
    except OSError as e:
        return tool_result("forensics.memory_forensics", target, status=STATUS_FAILED, error=str(e))

    if size < MIN_DUMP_SIZE:
        return tool_result(
            "forensics.memory_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary=f"File is only {size} bytes — too small to plausibly be a memory dump "
                    f"(expected at least {MIN_DUMP_SIZE} bytes).",
            error="file too small to be a memory dump",
        )

    try:
        import volatility3  # noqa: F401
        from volatility3.framework import contexts, automagic, plugins
    except ImportError:
        return tool_result(
            "forensics.memory_forensics", target,
            status=STATUS_UNAVAILABLE,
            findings=[Finding(
                title="volatility3 library not installed",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence="The 'volatility3' package is required to parse memory-dump structures "
                         "(process lists, handles, etc.); it is not declared in requirements.txt "
                         "or installed in this environment.",
                remediation="pip install volatility3",
                tool="forensics.memory_forensics",
                references=[],
            )],
            summary="Memory forensics unavailable: volatility3 not installed.",
            metadata={"file_size": size},
        )

    # volatility3 is present: attempt a minimal run of windows.pslist,
    # falling back to linux.pslist, using volatility3's documented
    # context/automagic/plugin-construction API (the same mechanism its own
    # `vol.py` CLI uses internally).
    rows: list[str] = []
    plugin_used = None
    errors: list[str] = []
    try:
        plugin_list = plugins.list_plugins()
        candidates = [
            "windows.pslist.PsList",
            "linux.pslist.PsList",
        ]
        for candidate in candidates:
            plugin_class = plugin_list.get(candidate)
            if plugin_class is None:
                errors.append(f"{candidate} not found in plugin registry")
                continue
            try:
                ctx = contexts.Context()
                ctx.config["automagic.LayerStacker.single_location"] = f"file:{os.path.abspath(target)}"
                base_config_path = "plugins"
                available = automagic.available_automagics(ctx)
                chosen = automagic.choose_automagic(available, plugin_class)
                automagic.run(chosen, ctx, plugin_class, base_config_path, progress_callback=None)
                constructed = plugins.construct_plugin(
                    ctx, chosen, plugin_class, base_config_path, None, None,
                )
                for row in constructed.run():
                    rows.append(str(row))
                    if len(rows) >= MAX_PROCESSES:
                        break
                plugin_used = candidate
                break
            except Exception as e:  # this candidate plugin/layer didn't match; try the next
                errors.append(f"{candidate}: {e}")
                continue
    except Exception as e:
        return tool_result(
            "forensics.memory_forensics", target,
            status=STATUS_FAILED,
            error=f"volatility3 plugin run failed: {e}",
            metadata={"file_size": size},
        )

    if plugin_used is None:
        return tool_result(
            "forensics.memory_forensics", target,
            status=STATUS_FAILED,
            error="No volatility3 pslist plugin could analyze this dump "
                  f"(tried windows.pslist, linux.pslist): {'; '.join(errors) if errors else 'unknown error'}",
            metadata={"file_size": size},
        )

    findings = [Finding(
        title="Process list extracted from memory dump",
        severity="info",
        confidence="high",
        affected_asset=target,
        evidence=f"Extracted {len(rows)} process record(s) via volatility3 {plugin_used}.",
        remediation="Review the process list for unexpected, unsigned, or masquerading process names.",
        tool="forensics.memory_forensics",
    )] if rows else []

    status = STATUS_COMPLETED if rows else STATUS_NO_FINDINGS
    return tool_result(
        "forensics.memory_forensics", target,
        status=status,
        findings=findings,
        summary=f"Extracted {len(rows)} process record(s) from memory dump via volatility3 {plugin_used}.",
        metadata={"file_size": size, "plugin_used": plugin_used, "processes": rows},
    )


tool_registry.register("forensics.memory_forensics", run, metadata={
    "name": "forensics.memory_forensics",
    "domain": "forensics",
    "status": "completed",
    "description": "Runs a minimal Volatility3 windows.pslist/linux.pslist plugin against a local memory-dump file to list real running processes (requires volatility3)",
    "parameters": {"target": "Path to a local memory-dump file"},
})
