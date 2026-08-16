from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry


class CryptoAgent(BaseAgent):
    name = "crypto_agent"
    description = "analysis agent for cryptography — certificate validation, cryptanalysis, and PKI reviews"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Each registered security tool is an isolation boundary: one broken
        # optional integration must not prevent the remaining analysis tools
        # from producing evidence.
        try:
            cert_val = tool_registry.get("cryptography.certificate_validation")
            result = cert_val(target=target)
            tools_used.append("cryptography.certificate_validation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"Certificate validation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            cryptanalysis = tool_registry.get("cryptography.cryptanalysis")
            result = cryptanalysis(target=target)
            tools_used.append("cryptography.cryptanalysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"Cryptanalysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            hash_analysis = tool_registry.get("cryptography.crypto_hash_analysis")
            result = hash_analysis(target=target)
            tools_used.append("cryptography.crypto_hash_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"Crypto hash analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            key_mgmt = tool_registry.get("cryptography.key_management")
            result = key_mgmt(target=target)
            tools_used.append("cryptography.key_management")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"Key management error: {e}", "severity": "low", "confidence": "medium"})

        try:
            pki = tool_registry.get("cryptography.pki_reviews")
            result = pki(target=target)
            tools_used.append("cryptography.pki_reviews")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"PKI review error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tls = tool_registry.get("cryptography.tls_testing")
            result = tls(target=target)
            tools_used.append("cryptography.tls_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"TLS testing error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name,
            target,
            status=status,
            findings=findings,
            summary=f"Cryptography analysis completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
