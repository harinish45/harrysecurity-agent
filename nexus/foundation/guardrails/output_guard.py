import re, json, os
from rich.console import Console

console = Console()

class OutputGuardError(Exception):
    pass

class OutputGuard:
    _blocked = [
        re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*[^\s]+"),
        re.compile(r"(?i)PRIVATE\s+KEY"),
        re.compile(r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        re.compile(r'(?i)(bash|sh|csh|zsh)\s+-c\s+"'),
        re.compile(r"(?i)\b(execve|system|popen|CreateProcess)\b"),
        re.compile(r"(?i)\[\s*eval\s*\("),
    ]

    @classmethod
    def validate(cls, output, context=None):
        if not output or not isinstance(output, str):
            return True
        for pattern in cls._blocked:
            if pattern.search(output):
                console.print(f"[red][OUTPUT GUARD] Blocked: {pattern.pattern}[/red]")
                raise OutputGuardError(f"Output blocked: {pattern.pattern}")
        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][OutputGuard] {message}[/dim]")
