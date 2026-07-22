from nexus.agents.base_agent import BaseAgent

class CodeReviewAgent(BaseAgent):
    name = "code_review_agent"
    description = "analysis agent for code_review"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"analysis","status":"stub","findings":[]}
