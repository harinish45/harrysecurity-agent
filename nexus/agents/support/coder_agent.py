from nexus.agents.base_agent import BaseAgent

class CoderAgent(BaseAgent):
    name = "coder_agent"
    description = "support agent for coder"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"support","status":"stub","findings":[]}
