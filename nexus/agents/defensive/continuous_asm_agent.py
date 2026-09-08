"""Scheduled re-recon with delta-only reporting (continuous attack-surface
management).

Runs the same recon tool set `recon_agent` uses, diffs the result against
the last stored snapshot for this target
(``engagements/<safe_target>/asm/last.json``), and only emits findings for
what actually changed (new subdomains/tech/ports, disappeared ones). Meant
to be invoked repeatedly for a bounty-mode target — either by hand or from
a cron/`nexus schedule` entry — rather than every run producing the full
recon findings list again.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result
from nexus.tools.registry import tool_registry

_RECON_TOOLS = [
    "reconnaissance.dns_recon",
    "reconnaissance.subdomain_enum",
    "reconnaissance.tech_fingerprint",
    "reconnaissance.whois_lookup",
]


class ContinuousAsmAgent(BaseAgent):
    name = "continuous_asm_agent"
    description = "defensive agent that re-runs recon and reports only what changed since the last snapshot"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, "unknown", status=STATUS_NO_FINDINGS, summary="No target specified")

        current = self._collect(target)
        snapshot_path = self._snapshot_path(target)
        previous = self._load_snapshot(snapshot_path)

        deltas = self._diff(previous, current)
        self._save_snapshot(snapshot_path, current)

        if not deltas:
            return tool_result(
                self.name, target,
                status=STATUS_NO_FINDINGS,
                summary=f"No attack-surface changes detected for {target} since last snapshot",
                metadata={"snapshot_path": str(snapshot_path)},
            )

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=deltas,
            summary=f"Detected {len(deltas)} attack-surface change(s) for {target} since last snapshot",
            metadata={"snapshot_path": str(snapshot_path)},
        )

    def _collect(self, target: str) -> dict:
        items: set[str] = set()
        for tool_name in _RECON_TOOLS:
            try:
                result = tool_registry.run(tool_name, target=target)
                for f in result.get("findings") or []:
                    label = f.get("title") if isinstance(f, dict) else str(f)
                    items.add(f"{tool_name}: {label}")
            except Exception as exc:  # noqa: BLE001 - one tool failing shouldn't drop the whole snapshot
                items.add(f"{tool_name}: [error] {exc}")
        return {"target": target, "items": sorted(items), "collected_at": datetime.now(timezone.utc).isoformat()}

    def _diff(self, previous: dict | None, current: dict) -> list[dict]:
        if not previous:
            return []  # first snapshot — nothing to diff against yet
        old_items = set(previous.get("items", []))
        new_items = set(current.get("items", []))
        deltas = []
        for added in sorted(new_items - old_items):
            deltas.append({
                "title": f"New attack-surface item: {added}",
                "severity": "info",
                "confidence": "high",
                "affected_asset": current["target"],
                "evidence": added,
                "tool": self.name,
            })
        for removed in sorted(old_items - new_items):
            deltas.append({
                "title": f"Attack-surface item no longer observed: {removed}",
                "severity": "info",
                "confidence": "medium",
                "affected_asset": current["target"],
                "evidence": removed,
                "tool": self.name,
            })
        return deltas

    @staticmethod
    def _snapshot_path(target: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", target).strip(".-") or "target"
        return Path("engagements") / safe / "asm" / "last.json"

    @staticmethod
    def _load_snapshot(path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _save_snapshot(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
