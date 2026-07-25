import json, os
from rich.console import Console

console = Console()

class LegalGuardError(Exception):
    pass

class LegalGuard:
    @classmethod
    def validate(cls, target=None, authorization=None):
        env_ack = os.environ.get("NEXUS_LEGAL_ACK", "")
        if authorization:
            ack = str(authorization).strip().upper()
            if ack == "I_HAVE_WRITTEN_AUTHORIZATION":
                console.print("[green][LEGAL GUARD] Authorization acknowledged.[/green]")
                return True
            console.print("[yellow][LEGAL GUARD] Weak/incorrect authorization string.[/yellow]")
        if env_ack == "I_HAVE_WRITTEN_AUTHORIZATION":
            console.print("[green][LEGAL GUARD] Authorization acknowledged via env.[/green]")
            return True
        console.print("[red][LEGAL GUARD] Authorization required. Set NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION[/red]")
        raise LegalGuardError("Authorization required but not provided.")

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][LegalGuard] {message}[/dim]")
