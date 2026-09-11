from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class RfSdrAgent(BaseAgent):
    name = "rf_sdr_agent"
    description = "specialized agent for RF/SDR — RTL-SDR, HackRF, radio protocol analysis, signal decoding, and replay testing"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("rf_sdr.rtl_sdr_analysis", target=target)
            tools_used.append("rf_sdr.rtl_sdr_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"RTL-SDR analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("rf_sdr.hackrf_experimentation", target=target)
            tools_used.append("rf_sdr.hackrf_experimentation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"HackRF experimentation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("rf_sdr.radio_protocol_analysis", target=target)
            tools_used.append("rf_sdr.radio_protocol_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Radio protocol analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("rf_sdr.signal_decoding", target=target)
            tools_used.append("rf_sdr.signal_decoding")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Signal decoding error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("rf_sdr.jammer_detection", target=target)
            tools_used.append("rf_sdr.jammer_detection")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Jammer detection error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("rf_sdr.replay_testing", target=target)
            tools_used.append("rf_sdr.replay_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Replay testing error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"RF/SDR testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )