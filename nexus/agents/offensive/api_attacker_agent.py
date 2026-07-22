from nexus.agents.base_agent import BaseAgent

class ApiAttackerAgent(BaseAgent):
    name = "api_attacker_agent"
    description = "offensive agent for api_attacker"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"offensive","status":"stub","findings":[]}
