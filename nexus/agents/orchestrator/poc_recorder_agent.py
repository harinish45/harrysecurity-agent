"""Records a replayable PoC transcript for every verified finding.

Downstream of `verification_agent`: once a finding is stamped ``verified``,
this agent persists a timestamped, replayable transcript (whatever
evidence/raw data the finding carries) to
``engagements/<mission_id>/poc/<finding_id>.json`` — the artifact a bounty
submission or an audit appendix actually needs, rather than making someone
reconstruct it from the report prose after the fact.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result


class PocRecorderAgent(BaseAgent):
    name = "poc_recorder_agent"
    description = "orchestrator agent that persists replayable PoC transcripts for verified findings"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        findings = kwargs.get("findings", []) or []
        mission_id = kwargs.get("mission_id", "mission")
        verified = [f for f in findings if f.get("verification_status") == "verified"]
        if not verified:
            return tool_result(self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                                summary="No verified findings to record PoC transcripts for")

        out_dir = Path("engagements") / self._safe_name(mission_id) / "poc"
        out_dir.mkdir(parents=True, exist_ok=True)

        written = []
        for f in verified:
            fid = self._safe_name(f.get("id", "F-UNKNOWN"))
            transcript = {
                "finding_id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "affected_asset": f.get("affected_asset"),
                "tool": f.get("tool"),
                "evidence": f.get("evidence"),
                "raw": f.get("raw"),
                "verification_status": f.get("verification_status"),
                "verification_detail": f.get("verification_detail"),
                "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            path = out_dir / f"{fid}.json"
            path.write_text(json.dumps(transcript, indent=2, default=str), encoding="utf-8")
            written.append(str(path))

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Recorded {len(written)} PoC transcript(s) to {out_dir}",
            metadata={"poc_files": written},
        )

    @staticmethod
    def _safe_name(value: str) -> str:
        import re
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value)).strip(".-")
        return cleaned or "unknown"
