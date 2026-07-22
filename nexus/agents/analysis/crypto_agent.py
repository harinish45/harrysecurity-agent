from nexus.agents.base_agent import BaseAgent

class CryptoAgent(BaseAgent):
    name = "crypto_agent"
    description = "analysis agent for crypto"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"analysis","status":"stub","findings":[]}
