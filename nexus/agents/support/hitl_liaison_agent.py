from nexus.agents.base_agent import BaseAgent

class HitlLiaisonAgent(BaseAgent):
    name = "hitl_liaison_agent"
    description = "support agent for hitl_liaison"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"support","status":"stub","findings":[]}
