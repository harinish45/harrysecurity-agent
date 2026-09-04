from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class MobileAgent(BaseAgent):
    name = "mobile_agent"
    description = "offensive agent for mobile — Android/iOS analysis, APK/IPA decompilation, and cert pinning bypass"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("mobile.android_analysis", target=target)
            tools_used.append("mobile.android_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Android analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("mobile.ios_analysis", target=target)
            tools_used.append("mobile.ios_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"iOS analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("mobile.apk_decompilation", target=target)
            tools_used.append("mobile.apk_decompilation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"APK decompilation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("mobile.ipa_analysis", target=target)
            tools_used.append("mobile.ipa_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"IPA analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("mobile.mobile_malware_analysis", target=target)
            tools_used.append("mobile.mobile_malware_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Mobile malware analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("mobile.cert_pinning_bypass", target=target)
            tools_used.append("mobile.cert_pinning_bypass")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Cert pinning bypass error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Mobile security testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )