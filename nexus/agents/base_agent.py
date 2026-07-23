from abc import ABC, abstractmethod
from typing import Optional

class AgentContext:
    def __init__(self, mission_id: str, target: str, findings: list = None):
        self.mission_id = mission_id
        self.target = target
        self.findings = findings or []
        self.history = []

    def add_to_history(self, entry: str) -> None:
        """Append a log entry to the mission history."""
        self.history.append(entry)

    def add_finding(self, finding: str) -> None:
        """Append a security finding to the findings list."""
        self.findings.append(finding)

class BaseAgent(ABC):
    name = "BaseAgent"
    def __init__(self, context: Optional[AgentContext] = None):
        self.context = context
    @abstractmethod
    async def run(self, task: str, **kwargs) -> dict:
        ...
    def log(self, msg): print(f"[{self.name}] {msg}")
