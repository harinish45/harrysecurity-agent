from nexus.agents.base_agent import BaseAgent

class DocWriterAgent(BaseAgent):
    name = "doc_writer_agent"
    description = "support agent for doc_writer"

    async def run(self, task: str, **kwargs) -> dict:
        return {"agent":self.name,"task":task,"tier":"support","status":"stub","findings":[]}
