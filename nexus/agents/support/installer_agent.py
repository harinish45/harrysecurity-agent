from nexus.agents.base_agent import BaseAgent

class InstallerAgent(BaseAgent):
    name = "installer_agent"
    description = "support agent for installer"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"support","status":"stub","findings":[]}
