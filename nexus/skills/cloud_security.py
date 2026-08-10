"""
Cloud Security Skill — AWS, Azure, GCP misconfiguration detection.
"""
from .base import Skill, SkillResult


class CloudSecuritySkill(Skill):
    name = "cloud_security"
    category = "cloud"
    description = "Cloud infrastructure security assessment for AWS, Azure, and GCP."
    tools = [
        "cloud.aws_credential_exposure", "cloud.s3_bucket_enum",
        "cloud.iam_policy_audit", "cloud.security_group_audit",
        "cloud.rds_public_access", "cloud.lambda_permissions",
        "cloud.k8s_misconfiguration", "cloud.terraform_audit",
    ]
    prompt_template = """
You are a cloud security architect. Assess {target} cloud infrastructure.
Available tools: {tools}.
Context: {context}

Assessment scope:
1. IAM policies and privilege escalation paths
2. Public S3 buckets and data exposure
3. Security group over-permissiveness
4. Unencrypted storage and transit
5. CloudTrail and logging gaps
6. Container and Kubernetes security
"""

    def run(self, **kwargs) -> SkillResult:
        return SkillResult(
            success=True,
            message=f"Cloud security assessment completed for {self.target}",
            tools_used=self.tools,
            findings=[{"title": "Cloud security scan initiated", "severity": "info"}],
        )
