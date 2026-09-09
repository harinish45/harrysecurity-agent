import os
import re
from rich.console import Console

console = Console()

class EscalationGuardError(Exception):
    pass

class EscalationGuard:
    # Audited and expanded — the original 10-keyword list missed several
    # clearly-destructive action classes (credential dumping, wipers, brute
    # forcing, data exfiltration, backdoors/keyloggers/ransomware-adjacent
    # actions) that would previously sail through with zero escalation.
    _destructive = [
        "exploit", "payload", "shell", "reverse", "bypass", "privilege_escalation",
        "rce", "lfi", "sqli", "xss", "credential_dump", "credential_harvest",
        "mimikatz", "kerberoast", "wiper", "wipe", "brute_force", "bruteforce",
        "data_exfil", "exfiltrat", "backdoor", "keylog", "ransomware",
        "destroy", "delete_all", "ddos", "dos_attack",
    ]

    @classmethod
    def validate(cls, tool_name=None, action=None, **kwargs):
        raw_name = (tool_name or action or "").lower()
        # Real, live gap caught by adversarial testing: the substring check
        # below is trivially evaded by any naming convention that inserts a
        # separator into a keyword — e.g. this codebase's OWN registered
        # `webapp.sql_injection` tool (an actual SQL-injection tester) never
        # matched "sqli" because of the underscore, while its sibling
        # `webapp.sqli` did. Stripping separators before matching closes
        # that whole evasion class (also catches "sq-li", "sq.li", etc.)
        # without needing to enumerate every naming variant by hand.
        lower_name = re.sub(r"[_\-.\s]+", "", raw_name)
        for _d in cls._destructive:
            if _d in raw_name or _d in lower_name:
                console.print(f"[red][ESCALATION GUARD] Action '{tool_name}' requires human approval.[/red]")
                if os.environ.get("ESCALATION_APPROVED", "").lower() != "true":
                    raise EscalationGuardError(f"Human approval required for: {tool_name}")
                # NOTE: ESCALATION_APPROVED is a process-wide, permanent
                # override, not scoped to this one action — once set, every
                # subsequent destructive action for the rest of the run
                # auto-approves with no further check. That's a deliberate
                # (if coarse) fit for this tool's single-operator-CLI usage
                # model (an operator sets it once before an engagement they
                # already know involves exploitation), but it means this is
                # NOT a per-action approval gate. Flagged here rather than
                # silently changed, since narrowing it to per-action approval
                # would be a real behavior change for existing operators.
                console.print(f"[green][ESCALATION GUARD] Override approved: {tool_name}[/green]")
                return True
        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][EscalationGuard] {message}[/dim]")
