from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ComplianceAuditorAgent(BaseAgent):
    name = "compliance_auditor_agent"
    description = "specialized agent for compliance auditing — ISO 27001, PCI DSS, GDPR, HIPAA, NIST, and policy reviews"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            tool = tool_registry.get("compliance.iso27001_audit")
            result = tool(target=target)
            tools_used.append("compliance.iso27001_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"ISO 27001 audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.pci_dss_audit")
            result = tool(target=target)
            tools_used.append("compliance.pci_dss_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"PCI DSS audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.gdpr_audit")
            result = tool(target=target)
            tools_used.append("compliance.gdpr_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"GDPR audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.hipaa_audit")
            result = tool(target=target)
            tools_used.append("compliance.hipaa_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"HIPAA audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.nist_800_53_audit")
            result = tool(target=target)
            tools_used.append("compliance.nist_800_53_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"NIST 800-53 audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.nist_csf_audit")
            result = tool(target=target)
            tools_used.append("compliance.nist_csf_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"NIST CSF audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.policy_reviews")
            result = tool(target=target)
            tools_used.append("compliance.policy_reviews")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Policy review error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.risk_assessments")
            result = tool(target=target)
            tools_used.append("compliance.risk_assessments")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Risk assessment error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("compliance.security_audits")
            result = tool(target=target)
            tools_used.append("compliance.security_audits")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Security audit error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Compliance auditing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )