from nexus.agents.base_agent import BaseAgent

class HardwareAgent(BaseAgent):
    name = "hardware_agent"
    description = "specialized agent for hardware"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"specialized","status":"stub","findings":[]}
