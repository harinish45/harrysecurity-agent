import os
from rich.console import Console

console = Console()

class EscalationGuardError(Exception):
    pass

class EscalationGuard:
    _destructive = ["exploit", "payload", "shell", "reverse", "bypass", "privilege_escalation", "rce", "lfi", "sqli", "xss"]

    @classmethod
    def validate(cls, tool_name=None, action=None, **kwargs):
        lower_name = (tool_name or action or "").lower()
        for _d in cls._destructive:
            if _d in lower_name:
                console.print(f"[red][ESCALATION GUARD] Action '{tool_name}' requires human approval.[/red]")
                if os.environ.get("ESCALATION_APPROVED", "").lower() != "true":
                    raise EscalationGuardError(f"Human approval required for: {tool_name}")
                console.print(f"[green][ESCALATION GUARD] Override approved: {tool_name}[/green]")
                return True
        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][EscalationGuard] {message}[/dim]")
