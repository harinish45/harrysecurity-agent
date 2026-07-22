from nexus.agents.base_agent import BaseAgent

class ThreatIntelAgent(BaseAgent):
    name = "threat_intel_agent"
    description = "analysis agent for threat_intel"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"analysis","status":"stub","findings":[]}
