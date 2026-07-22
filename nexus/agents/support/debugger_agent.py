from nexus.agents.base_agent import BaseAgent

class DebuggerAgent(BaseAgent):
    name = "debugger_agent"
    description = "support agent for debugger"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"support","status":"stub","findings":[]}
