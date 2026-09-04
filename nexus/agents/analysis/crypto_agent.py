from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class CryptoAgent(BaseAgent):
    name = "crypto_agent"
    description = "analysis agent for cryptography — certificate validation, cryptanalysis, and PKI reviews"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Certificate validation
        try:
            result = tool_registry.run("cryptography.certificate_validation", target=target)
            tools_used.append("cryptography.certificate_validation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Certificate validation error: {e}", "severity": "low", "confidence": "medium"})

        # Cryptanalysis
        try:
            result = tool_registry.run("cryptography.cryptanalysis", target=target)
            tools_used.append("cryptography.cryptanalysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Cryptanalysis error: {e}", "severity": "low", "confidence": "medium"})

        # Crypto hash analysis
        try:
            result = tool_registry.run("cryptography.crypto_hash_analysis", target=target)
            tools_used.append("cryptography.crypto_hash_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Crypto hash analysis error: {e}", "severity": "low", "confidence": "medium"})

        # Key management
        try:
            result = tool_registry.run("cryptography.key_management", target=target)
            tools_used.append("cryptography.key_management")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Key management error: {e}", "severity": "low", "confidence": "medium"})

        # PKI reviews
        try:
            result = tool_registry.run("cryptography.pki_reviews", target=target)
            tools_used.append("cryptography.pki_reviews")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"PKI review error: {e}", "severity": "low", "confidence": "medium"})

        # TLS testing
        try:
            result = tool_registry.run("cryptography.tls_testing", target=target)
            tools_used.append("cryptography.tls_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"TLS testing error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Cryptography analysis completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
