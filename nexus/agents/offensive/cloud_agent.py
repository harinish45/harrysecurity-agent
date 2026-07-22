from nexus.agents.base_agent import BaseAgent

class CloudAgent(BaseAgent):
    name = "cloud_agent"
    description = "offensive agent for cloud"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"offensive","status":"stub","findings":[]}
