from nexus.agents.base_agent import BaseAgent

class ReporterAgent(BaseAgent):
    name = "reporter_agent"
    description = "support agent for reporter"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"support","status":"stub","findings":[]}
