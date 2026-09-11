from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class CloudAgent(BaseAgent):
    name = "cloud_agent"
    description = "offensive agent for cloud — AWS, Azure, GCP, Kubernetes, IAM, and container security testing"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("cloud.aws_review", target=target)
            tools_used.append("cloud.aws_review")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"AWS review error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("cloud.azure_assessment", target=target)
            tools_used.append("cloud.azure_assessment")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Azure assessment error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("cloud.gcp_review", target=target)
            tools_used.append("cloud.gcp_review")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"GCP review error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("cloud.kubernetes_security", target=target)
            tools_used.append("cloud.kubernetes_security")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Kubernetes security error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("cloud.iam_audit", target=target)
            tools_used.append("cloud.iam_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"IAM audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("cloud.s3_review", target=target)
            tools_used.append("cloud.s3_review")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"S3 review error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("cloud.container_scanning", target=target)
            tools_used.append("cloud.container_scanning")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Container scanning error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("cloud.secret_detection", target=target)
            tools_used.append("cloud.secret_detection")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Secret detection error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Cloud security testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )