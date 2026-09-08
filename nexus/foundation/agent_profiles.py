"""Mode-separation profiles for the CLI's top-level commands.

Each profile restricts which tool domains `OrchestrationEngine._plan_mission`
is allowed to hand the LLM planner (so `nexus ctf --category web` doesn't
load AD/wireless tools into context — wasted tokens/turns on the wrong
domain), and names which `report_tone_agent` template the mission's findings
should be rendered through at the end. `mode` is passed straight through to
`OrchestrationEngine.run_mission`/`report_tone_agent`, so it must match a key
in `report_tone_agent._MODE_TEMPLATES`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_ALL_DOMAINS = (
    "reconnaissance", "network", "webapp", "wireless", "active_directory",
    "cloud", "mobile", "malware", "reverse_engineering", "exploit_dev",
    "forensics", "incident_response", "threat_intel", "iam", "compliance", "appsec", "ai_security",
)


@dataclass(frozen=True)
class AgentProfile:
    name: str
    mode: str
    allowed_domains: tuple[str, ...]
    objective_hint: str
    description: str


PROFILES: dict[str, AgentProfile] = {
    "pentest": AgentProfile(
        name="pentest", mode="pentest", allowed_domains=_ALL_DOMAINS,
        objective_hint="full_assessment",
        description="Authorized engagement, full guardrails, all domains available.",
    ),
    "bounty": AgentProfile(
        name="bounty", mode="bounty",
        allowed_domains=("reconnaissance", "network", "webapp", "cloud", "mobile", "appsec"),
        objective_hint="bounty_hunt",
        description="Scope pulled from a bounty program; web/API/cloud/mobile-focused, bounty-format report.",
    ),
    "ctf": AgentProfile(
        name="ctf", mode="ctf",
        allowed_domains=("webapp", "network", "reverse_engineering", "malware", "exploit_dev", "appsec"),
        objective_hint="ctf_solve",
        description="pwn/web/crypto/rev/forensics/misc category solving, CTF-writeup-format report.",
    ),
    "redteam": AgentProfile(
        name="redteam", mode="redteam",
        allowed_domains=_ALL_DOMAINS,
        objective_hint="adversary_emulation",
        description="TTP-chain adversary emulation, MITRE ATT&CK-mapped, redteam-format report.",
    ),
    "blueteam": AgentProfile(
        name="blueteam", mode="blueteam",
        allowed_domains=("threat_intel", "incident_response", "forensics", "network", "malware"),
        objective_hint="detection_and_response",
        description="Defensive: detection engineering, log/incident triage, incident-format report.",
    ),
    "compliance": AgentProfile(
        name="compliance", mode="compliance",
        allowed_domains=("compliance", "iam", "cloud", "appsec"),
        objective_hint="control_gap_analysis",
        description="Control-mapping and gap analysis against a named framework, compliance-format report.",
    ),
}


def get_profile(name: str) -> AgentProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise KeyError(f"Unknown agent profile '{name}'. Available: {', '.join(sorted(PROFILES))}") from exc
