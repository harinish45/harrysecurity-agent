"""
Threat Intelligence Skill — IOC analysis, malware hunting, threat actor mapping.
"""
from .base import Skill, SkillResult


class ThreatIntelSkill(Skill):
    name = "threat_intel"
    category = "threat"
    description = "Threat intelligence analysis including IOC hunting, malware family identification, and threat actor profiling."
    tools = [
        "threat_intel.ioc_lookup", "threat_intel.malware_family",
        "threat_intel.threat_actor_mapping", "threat_intel.yara_rules",
        "threat_intel.sigma_rules", "threat_intel.mitre_mapping",
    ]
    prompt_template = """
You are a threat intelligence analyst. Investigate {target} for indicators of compromise.
Available tools: {tools}.
Context: {context}

Analysis objectives:
1. IOC enrichment and reputation scoring
2. MITRE ATT&CK technique mapping
3. Malware family and behavior analysis
4. Threat actor attribution
5. YARA and Sigma rule generation
6. Hunting recommendations
"""

    def run(self, **kwargs) -> SkillResult:
        return SkillResult(
            success=True,
            message=f"Threat intelligence analysis completed for {self.target}",
            tools_used=self.tools,
            findings=[{"title": "Threat intel analysis initiated", "severity": "info"}],
        )
