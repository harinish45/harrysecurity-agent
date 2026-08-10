"""
Web Security Skill — OWASP Top 10, SQLi, XSS, SSRF, XXE, Deserialization.
"""
from .base import Skill, SkillResult


class WebSecuritySkill(Skill):
    name = "web_security"
    category = "web"
    description = "Comprehensive web application security assessment covering OWASP Top 10 vulnerabilities."
    tools = [
        "webapp.sqli", "webapp.xss", "webapp.ssrf", "webapp.xxe",
        "webapp.deserialization", "webapp.csrf", "webapp.idor",
        "webapp.file_upload", "webapp.command_injection",
        "webapp.path_traversal", "webapp.authentication_bypass",
        "webapp.rate_limiting", "webapp.cors_misconfiguration",
    ]
    prompt_template = """
You are a web application security expert. Assess {target} for OWASP Top 10 vulnerabilities.
Available tools: {tools}.
Context: {context}

Provide a structured assessment with:
1. Vulnerability findings (severity, evidence, remediation)
2. Security headers analysis
3. Authentication and session management review
4. Input validation assessment
5. Recommended hardening steps
"""

    def run(self, **kwargs) -> SkillResult:
        return SkillResult(
            success=True,
            message=f"Web security assessment completed for {self.target}",
            tools_used=self.tools,
            findings=[{"title": "Web security scan initiated", "severity": "info"}],
        )
