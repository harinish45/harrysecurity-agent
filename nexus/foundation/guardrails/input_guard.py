import re, json, os
from rich.console import Console

console = Console()

class InputGuardError(Exception):
    pass

class InputGuard:
    _patterns = [
        re.compile(r"(?i)ignore\s+(all\s+)?(previous\s+)?(instructions|rules|guidelines)"),
        re.compile(r"(?i)IGNORE\s+.*?SYSTEM\s+PROMPT"),
        re.compile(r"(?i)disregard\s+(all\s+)?(prior|previous)"),
        re.compile(r"(?i)pretend\s+you\s+are\s+admin"),
        re.compile(r"(?i)you\s+are\s+now\s+in\s+developer\s+mode"),
        re.compile(r"(?i)run\s+.*?(rm\s+-rf|del\s+/f|format\s+c:)"),
        re.compile(r"(?i)\$\{.*?\}"),
        re.compile(r"(?i)<script.*?>"),
        re.compile(r"(?i)/etc/passwd"),
        re.compile(r"(?i)\.\./"),
        re.compile(r"(?i)(DROP\s+TABLE|DELETE\s+FROM|UPDATE.*?SET)"),
    ]

    @classmethod
    def validate(cls, payload, context=None):
        if not payload or not isinstance(payload, str):
            return True
        for pattern in cls._patterns:
            if pattern.search(payload):
                console.print(f"[red][INPUT GUARD] Blocked: {pattern.pattern}[/red]")
                raise InputGuardError(f"Input blocked: {pattern.pattern}")
        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][InputGuard] {message}[/dim]")
