import re, json, os
from rich.console import Console

from ._entropy import shannon_entropy

console = Console()

class OutputGuardError(Exception):
    pass

class OutputGuard:
    ENTROPY_THRESHOLD = 4.5
    ENTROPY_MIN_TOKEN_LENGTH = 32

    # `redact_findings()` (called by ToolExecutor before this guard runs)
    # replaces a secret's *value* with the literal marker "[REDACTED]" but
    # keeps the "key=" prefix for readability — without an exclusion for
    # that marker, it is itself a non-whitespace token and the pattern
    # re-blocks its own sanitized output, turning a legitimate "found an
    # exposed API key" finding into a dropped STATUS_FAILED result even
    # after successful redaction. The lookahead requires "[REDACTED]" to be
    # a *complete* token — followed by whitespace, one of the punctuation
    # characters redact_findings()'s own value pattern (`[^\s,;]+`) already
    # stops at, or end-of-string — before exempting it. A bare
    # `(?!\[REDACTED\])` would let `api_key=[REDACTED]realSecretHere`
    # (marker glued directly to more content, no separating whitespace)
    # smuggle a real secret past this guard by hiding behind the exemption.
    _blocked = [
        re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*(?!\[REDACTED\](?:[\s,;.!?)\]]|$))[^\s]+"),
        re.compile(r"(?i)PRIVATE\s+KEY"),
        re.compile(r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        re.compile(r'(?i)(bash|sh|csh|zsh)\s+-c\s+"'),
        re.compile(r"(?i)\b(execve|system|popen|CreateProcess)\b"),
        re.compile(r"(?i)\[\s*eval\s*\("),
    ]

    # Bare tokens (not key=value / key: value shaped) that look like leaked
    # secrets: long alphanumeric/base64-ish runs.
    _bare_token_pattern = re.compile(r"[A-Za-z0-9+/_-]{%d,}" % ENTROPY_MIN_TOKEN_LENGTH)

    @classmethod
    def _layer_high_entropy_token(cls, output):
        """Flag bare high-entropy tokens that don't match the key=value shape."""
        for match in cls._bare_token_pattern.finditer(output):
            token = match.group(0)
            entropy = shannon_entropy(token)
            if entropy > cls.ENTROPY_THRESHOLD:
                console.print(f"[red][OUTPUT GUARD] Blocked: high entropy token (entropy={entropy:.2f})[/red]")
                raise OutputGuardError(f"Output blocked: high entropy token (entropy={entropy:.2f})")
        return True

    @classmethod
    def validate(cls, output, context=None):
        if not output or not isinstance(output, str):
            return True
        for pattern in cls._blocked:
            if pattern.search(output):
                console.print(f"[red][OUTPUT GUARD] Blocked: {pattern.pattern}[/red]")
                raise OutputGuardError(f"Output blocked: {pattern.pattern}")
        cls._layer_high_entropy_token(output)
        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][OutputGuard] {message}[/dim]")
