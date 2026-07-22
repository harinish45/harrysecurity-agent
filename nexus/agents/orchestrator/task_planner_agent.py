from nexus.agents.base_agent import BaseAgent

class TaskPlannerAgent(BaseAgent):
    name = "task_planner_agent"
    description = "orchestrator agent for task_planner"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"orchestrator","status":"stub","findings":[]}
