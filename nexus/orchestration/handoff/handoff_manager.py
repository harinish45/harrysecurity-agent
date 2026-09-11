"""Ties context transfer and escalation together into the one call
FlowController makes between dependency batches."""
from __future__ import annotations

from typing import Any

from nexus.orchestration.handoff.context_transfer import ContextTransfer
from nexus.orchestration.handoff.escalation import Escalation


class HandoffManager:
    @staticmethod
    def prepare_next_batch(completed_results: list[dict[str, Any]]) -> dict[str, Any]:
        context = ContextTransfer.package(completed_results)
        all_findings = [
            f for r in completed_results if isinstance(r, dict)
            for f in (r.get("findings") or []) if isinstance(f, dict)
        ]
        context["escalations"] = Escalation.check(all_findings)
        return context
