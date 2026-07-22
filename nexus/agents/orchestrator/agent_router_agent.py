from nexus.agents.base_agent import BaseAgent

class AgentRouterAgent(BaseAgent):
    name = "agent_router_agent"
    description = "orchestrator agent for agent_router"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"orchestrator","status":"stub","findings":[]}
