from nexus.agents.base_agent import BaseAgent
class CustomAgent(BaseAgent):
    name = 'custom'
    async def run(self, task): return {'status':'stub'}
