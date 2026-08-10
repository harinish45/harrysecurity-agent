"""
NEXUS-STRIKE Skills Plugin Registry

Skills are high-level orchestrations of tools, invoked by the LLM router
or directly via the CLI/API. They provide structured, repeatable security
assessments across different domains.
"""
from typing import Callable, Dict, List, Any
from dataclasses import dataclass

@dataclass
class Skill:
    name: str
    category: str
    description: str
    tools: List[str]
    prompt_template: str
    handler: Callable


class SkillsRegistry:
    def __init__(self):
        self._skills: Dict[str, Skill] = {}

    def register(self, skill: Skill):
        """Register a new skill."""
        self._skills[skill.name] = skill

    def get(self, name: str) -> Skill:
        """Get a skill by name."""
        return self._skills.get(name)

    def list_by_category(self, category: str) -> List[Skill]:
        """List all skills in a specific category."""
        return [s for s in self._skills.values() if s.category == category]

    def list_all(self) -> List[Skill]:
        """List all registered skills."""
        return list(self._skills.values())


skills_registry = SkillsRegistry()


# =============================================================================
# Built-in Skills
# =============================================================================

def _default_handler(target: str, **kwargs) -> Dict[str, Any]:
    """Default skill handler that returns a structured response."""
    return {
        "status": "completed",
        "skill": kwargs.get("skill_name", "unknown"),
        "target": target,
        "findings": [],
        "message": f"Skill executed successfully on {target}"
    }


# 1. Web Application Security
skills_registry.register(Skill(
    name="webapp_audit",
    category="Web",
    description="Comprehensive web application security assessment",
    tools=["sql_injection", "xxe", "ssrf", "deserialization"],
    prompt_template="Perform a comprehensive web application security audit on {target}. Focus on OWASP Top 10 vulnerabilities.",
    handler=_default_handler
))

# 2. Active Directory
skills_registry.register(Skill(
    name="ad_audit",
    category="Active Directory",
    description="Active Directory security posture assessment",
    tools=["kerberoast", "asrep_roast", "golden_ticket", "bloodhound"],
    prompt_template="Assess the Active Directory security posture of {target}. Look for misconfigurations, weak credentials, and privilege escalation paths.",
    handler=_default_handler
))

# 3. Network Reconnaissance
skills_registry.register(Skill(
    name="network_recon",
    category="Network",
    description="Network infrastructure discovery and mapping",
    tools=["arp_spoof", "dhcp_starvation", "waf_detect"],
    prompt_template="Perform network reconnaissance on {target}. Map the infrastructure, identify open services, and detect defensive mechanisms.",
    handler=_default_handler
))

# 4. Cloud Security
skills_registry.register(Skill(
    name="cloud_audit",
    category="Cloud",
    description="Cloud infrastructure security assessment",
    tools=["aws_credential_exposure"],
    prompt_template="Assess the cloud security posture of {target}. Look for exposed credentials, misconfigured IAM policies, and public-facing resources.",
    handler=_default_handler
))

# 5. Threat Intelligence
skills_registry.register(Skill(
    name="threat_intel",
    category="Threat Intel",
    description="Threat intelligence gathering and correlation",
    tools=["cve_enrichment"],
    prompt_template="Gather threat intelligence related to {target}. Correlate findings with known CVEs, threat actor TTPs, and recent disclosures.",
    handler=_default_handler
))

# 6. Compliance
skills_registry.register(Skill(
    name="compliance_check",
    category="Compliance",
    description="Security compliance verification",
    tools=["policy_audit"],
    prompt_template="Verify the security compliance of {target} against industry standards (CIS, NIST, ISO 27001).",
    handler=_default_handler
))

# 7. Code Security
skills_registry.register(Skill(
    name="code_audit",
    category="Code",
    description="Source code security analysis",
    tools=["static_analysis", "secret_scanning"],
    prompt_template="Analyze the source code of {target} for security vulnerabilities, hardcoded secrets, and insecure coding practices.",
    handler=_default_handler
))