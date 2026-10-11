from abc import ABC, abstractmethod
from typing import Any, Optional
from nexus.foundation.logging import logger


class AgentContext:
    """Carries mission state, findings, and shared intelligence across agents."""

    def __init__(self, mission_id: str, target: str, findings: list | None = None) -> None:
        self.mission_id: str = mission_id
        self.target: str = target
        self.findings: list[Any] = findings if findings is not None else []
        self.history: list[str] = []
        self.shared_data: dict[str, Any] = {}
        self.telemetry: list[dict[str, Any]] = []

    def add_to_history(self, entry: str) -> None:
        """Append a log entry to the mission history."""
        self.history.append(str(entry))

    def add_finding(self, finding: Any) -> None:
        """Append a security finding to the findings list."""
        self.findings.append(finding)

    def set_shared(self, key: str, value: Any) -> None:
        """Set shared data accessible to collaborating agents."""
        self.shared_data[key] = value

    def get_shared(self, key: str, default: Any = None) -> Any:
        """Retrieve shared data stored by previous agents."""
        return self.shared_data.get(key, default)

    def record_telemetry(self, agent_name: str, event: str, data: dict[str, Any] | None = None) -> None:
        """Record operational telemetry without polluting security findings."""
        self.telemetry.append({
            "agent": agent_name,
            "event": event,
            "data": data or {},
        })


class BaseAgent(ABC):
    """Abstract base class for all autonomous security agents."""

    name: str = "BaseAgent"
    description: str = ""

    def __init__(self, context: Optional[AgentContext] = None) -> None:
        self.context: Optional[AgentContext] = context

    @abstractmethod
    async def run(self, task: str, **kwargs: Any) -> dict[str, Any]:
        """Execute the agent's autonomous task."""
        ...

    def log(self, msg: str) -> None:
        """Log structured info using central logger instead of print statements."""
        logger.info(f"[{self.name}] {msg}")

    def log_warning(self, msg: str) -> None:
        """Log structured warning message."""
        logger.warning(f"[{self.name}] {msg}")

    def log_error(self, msg: str) -> None:
        """Log structured error message."""
        logger.error(f"[{self.name}] {msg}")

    def execute_tool(self, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        """Safely execute a tool via the guardrailed ToolRegistry.

        Captures operational errors cleanly without raising exceptions
        or corrupting downstream security findings.
        """
        try:
            from nexus.tools.registry import tool_registry
            return tool_registry.run(tool_name, target=target, **kwargs)
        except Exception as exc:
            self.log_warning(f"Tool {tool_name} execution encountered error: {exc}")
            if self.context:
                self.context.record_telemetry(self.name, "tool_error", {"tool": tool_name, "error": str(exc)})
            return {"status": "failed", "error": str(exc), "findings": []}

    def deduplicate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate findings based on title and affected asset."""
        seen: set[tuple[str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                deduped.append(finding)
                continue
            key = (str(finding.get("title", "")).strip(), str(finding.get("affected_asset", "")).strip())
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        return deduped

