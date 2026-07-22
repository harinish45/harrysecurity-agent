from nexus.agents.base_agent import BaseAgent

class ReconAgent(BaseAgent):
    name = "recon_agent"
    description = "offensive agent for recon"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"offensive","status":"stub","findings":[]}
