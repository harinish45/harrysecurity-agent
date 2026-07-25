from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class HitlLiaisonAgent(BaseAgent):
    name = "hitl_liaison_agent"
    description = "support agent for HITL liaison — manages human approval gates and feedback loops"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        findings = kwargs.get("findings", []) or []
        review_items = []
        approval_requests = []
        feedback = kwargs.get("feedback", {}) or {}

        for idx, f in enumerate(findings, 1):
            review_items.append({
                "id": f"REV-{idx:03d}",
                "finding_id": f.get("id", f"F-{idx:03d}"),
                "title": f.get("title", "Untitled"),
                "severity": f.get("severity", "info"),
                "confidence": f.get("confidence", "medium"),
                "approval_status": "pending",
                "human_notes": "",
            })
            approval_requests.append({
                "request_id": f"APPR-{idx:03d}",
                "finding_id": f"REV-{idx:03d}",
                "status": "awaiting_review",
                "assigned_to": "human_operator",
                "deadline": "pending",
            })

        if feedback:
            for item in review_items:
                fid = item["finding_id"]
                if fid in feedback:
                    item["approval_status"] = feedback[fid].get("status", "pending")
                    item["human_notes"] = feedback[fid].get("notes", "")

        approved = sum(1 for r in review_items if r["approval_status"] == "approved")
        rejected = sum(1 for r in review_items if r["approval_status"] == "rejected")
        pending = sum(1 for r in review_items if r["approval_status"] == "pending")

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"HITL review processed: {approved} approved, {rejected} rejected, {pending} pending",
            metadata={
                "review_items": review_items,
                "approval_requests": approval_requests,
                "feedback_captured": bool(feedback),
                "review_summary": {
                    "total": len(review_items),
                    "approved": approved,
                    "rejected": rejected,
                    "pending": pending,
                },
            },
        )
