from nexus.agents.base_agent import BaseAgent

class BlueTeamAgent(BaseAgent):
    name = "blue_team_agent"
    description = "defensive agent for blue_team"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"defensive","status":"stub","findings":[]}
