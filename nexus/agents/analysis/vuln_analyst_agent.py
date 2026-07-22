from nexus.agents.base_agent import BaseAgent

class VulnAnalystAgent(BaseAgent):
    name = "vuln_analyst_agent"
    description = "analysis agent for vuln_analyst"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"analysis","status":"stub","findings":[]}
