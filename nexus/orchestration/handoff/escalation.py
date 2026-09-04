"""Flags critical/high-severity findings for human approval, reusing the
existing EscalationGuard rather than re-implementing approval logic."""
from __future__ import annotations

from nexus.foundation.guardrails import EscalationGuard
from nexus.foundation.guardrails.escalation_guard import EscalationGuardError

_ESCALATE_SEVERITIES = {"critical", "high"}


class Escalation:
    @staticmethod
    def check(findings: list[dict]) -> list[dict]:
        records = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            severity = str(f.get("severity", "info")).lower()
            if severity not in _ESCALATE_SEVERITIES:
                continue

            record = {"title": f.get("title", "untitled"), "severity": severity, "approved": True}
            try:
                EscalationGuard.validate(action=f.get("title", ""))
            except EscalationGuardError as exc:
                record["approved"] = False
                record["reason"] = str(exc)
            records.append(record)
        return records
