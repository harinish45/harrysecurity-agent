from abc import ABC, abstractmethod
from typing import Optional

class AgentContext:
    def __init__(self, mission_id: str, target: str, findings: list = None):
        self.mission_id = mission_id
        self.target = target
        self.findings = findings or []
        self.history = []

class BaseAgent(ABC):
    name = "BaseAgent"
    def __init__(self, context: Optional[AgentContext] = None):
        self.context = context
    @abstractmethod
    async def run(self, task: str, **kwargs) -> dict:
        ...
    def log(self, msg): print(f"[{self.name}] {msg}")
