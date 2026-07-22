from nexus.agents.base_agent import BaseAgent

class SearcherAgent(BaseAgent):
    name = "searcher_agent"
    description = "support agent for searcher"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"support","status":"stub","findings":[]}
