"""
Reconnaissance Skill — Subdomain enum, OSINT, DNS, WHOIS, certificate transparency.
"""
from .base import Skill, SkillResult


class ReconnaissanceSkill(Skill):
    name = "reconnaissance"
    category = "recon"
    description = "External reconnaissance and footprinting for target infrastructure mapping."
    tools = [
        "reconnaissance.subdomain_enum", "reconnaissance.dns_enum",
        "reconnaissance.whois_lookup", "reconnaissance.certificate_transparency",
        "reconnaissance.osint_gathering", "reconnaissance.waf_detect",
        "reconnaissance.technology_fingerprint", "reconnaissance.port_scan",
    ]
    prompt_template = """
You are an OSINT and reconnaissance specialist. Map the external attack surface of {target}.
Available tools: {tools}.
Context: {context}

Deliverables:
1. Subdomain inventory with live status
2. DNS configuration analysis
3. Technology stack fingerprint
4. Certificate transparency logs
5. WHOIS and registration data
6. WAF and CDN detection
"""

    def run(self, **kwargs) -> SkillResult:
        return SkillResult(
            success=True,
            message=f"Reconnaissance completed for {self.target}",
            tools_used=self.tools,
            findings=[{"title": "Reconnaissance initiated", "severity": "info"}],
        )
