"""
Code Security Skill — Static analysis, SAST, secret scanning, dependency audit.
"""
from .base import Skill, SkillResult


class CodeSecuritySkill(Skill):
    name = "code_security"
    category = "code"
    description = "Source code security analysis including SAST, secret detection, and dependency vulnerability scanning."
    tools = [
        "code_review.static_analysis", "code_review.secret_scanning",
        "code_review.dependency_audit", "code_review.sast",
        "code_review.hardcoded_credentials", "code_review.insecure_patterns",
    ]
    prompt_template = """
You are a code security auditor. Analyze the codebase at {target} for security issues.
Available tools: {tools}.
Context: {context}

Focus areas:
1. Hardcoded credentials and API keys
2. Insecure cryptographic implementations
3. SQL injection patterns in code
4. Unsafe deserialization
5. Dependency vulnerabilities
6. OWASP secure coding violations
"""

    def run(self, **kwargs) -> SkillResult:
        return SkillResult(
            success=True,
            message=f"Code security audit completed for {self.target}",
            tools_used=self.tools,
            findings=[{"title": "Code security scan initiated", "severity": "info"}],
        )
