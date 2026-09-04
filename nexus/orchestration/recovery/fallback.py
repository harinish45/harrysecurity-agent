"""Graceful degradation when a mission phase's designated agent can't run —
falls back to a related, more-general agent rather than dropping the phase
silently, and produces a truthfully-failed result (never a fabricated
"completed") when there is no reasonable fallback."""
from __future__ import annotations

from nexus.foundation.schema import STATUS_FAILED, tool_result

# Maps a specialist agent to a more general one that can still produce some
# signal on the same target when the specialist is unavailable or errors out.
_FALLBACK_AGENT: dict[str, str] = {
    "webapp_agent": "recon_agent",
    "api_attacker_agent": "webapp_agent",
    "exploit_agent": "vuln_analyst_agent",
    "wireless_agent": "recon_agent",
    "mobile_agent": "recon_agent",
    "cloud_agent": "recon_agent",
    "ad_agent": "network_agent",
    "redteam_agent": "recon_agent",
    "physical_pen_agent": "recon_agent",
    "social_eng_agent": "osint_analyst_agent",
    "phishing_agent": "osint_analyst_agent",
}


class Fallback:
    @staticmethod
    def agent_for(agent_name: str) -> str | None:
        return _FALLBACK_AGENT.get(agent_name)

    @staticmethod
    def degraded_result(agent_name: str, target: str, task: str, reason: str) -> dict:
        return tool_result(
            agent_name, target or "unknown",
            status=STATUS_FAILED,
            error=reason,
            summary=f"{agent_name} could not complete '{task[:60]}' and no fallback produced findings",
            metadata={"degraded": True},
        )
