#!/usr/bin/env python3
import os

BASE = r'c:\Documents\Projects\Cyber Secuirty Agent\nexus-strike'
GR_DIR = os.path.join(BASE, 'nexus', 'foundation', 'guardrails')

GUARDRAIL_IMPLS = {
    'input_guard.py': '''
import re, json, os
from rich.console import Console

console = Console()

class InputGuardError(Exception):
    pass

class InputGuard:
    _patterns = [
        re.compile(r"(?i)ignore\\s+(all\\s+)?(previous\\s+)?(instructions|rules|guidelines)"),
        re.compile(r"(?i)IGNORE\\s+.*?SYSTEM\\s+PROMPT"),
        re.compile(r"(?i)disregard\\s+(all\\s+)?(prior|previous)"),
        re.compile(r"(?i)pretend\\s+you\\s+are\\s+admin"),
        re.compile(r"(?i)you\\s+are\\s+now\\s+in\\s+developer\\s+mode"),
        re.compile(r"(?i)run\\s+.*?(rm\\s+-rf|del\\s+/f|format\\s+c:)"),
        re.compile(r"(?i)\\$\\{.*?\\}"),
        re.compile(r"(?i)<script.*?>"),
        re.compile(r"(?i)/etc/passwd"),
        re.compile(r"(?i)\\.\\./"),
        re.compile(r"(?i)(DROP\\s+TABLE|DELETE\\s+FROM|UPDATE.*?SET)"),
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
''',
    'output_guard.py': '''
import re, json, os
from rich.console import Console

console = Console()

class OutputGuardError(Exception):
    pass

class OutputGuard:
    _blocked = [
        re.compile(r"(?i)(password|passwd|secret|api_key|token)\\s*[:=]\\s*[^\\s]+"),
        re.compile(r"(?i)PRIVATE\\s+KEY"),
        re.compile(r"(?i)-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"),
        re.compile(r"(?i)(bash|sh|csh|zsh)\\s+-c\\s+\""),
        re.compile(r"(?i)\\b(execve|system|popen|CreateProcess)\\b"),
        re.compile(r"(?i)\\[\\s*eval\\s*\\("),
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
''',
    'scope_guard.py': '''
import re, json, os, ipaddress
from urllib.parse import urlparse
from rich.console import Console

console = Console()

class ScopeGuardError(Exception):
    pass

class ScopeGuard:
    _protected = [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "0.0.0.0/8", "::1", "localhost",
        "127.0.0.1", "0.0.0.0",
    ]

    @classmethod
    def validate(cls, target, mode="scan"):
        if not target:
            return True
        if isinstance(target, str):
            hostname = urlparse(target if "://" in target else f"http://{target}").hostname or target
            hostname = hostname.lower()
            if hostname in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
                console.print(f"[yellow][SCOPE GUARD] Allowing localhost: {hostname}[/yellow]")
                return True
            for protected in cls._protected:
                try:
                    if "/" in protected:
                        net = ipaddress.ip_network(protected, strict=False)
                        addr = ipaddress.ip_address(hostname) if not any(c in hostname for c in "abcdefghijklmnopqrstuvwxyz") else None
                        if addr and addr in net:
                            raise ScopeGuardError(f"Target {hostname} is in protected range {protected}")
                    elif hostname == protected:
                        raise ScopeGuardError(f"Target {hostname} is protected")
                except (ScopeGuardError, ValueError) as e:
                    if "is in protected range" in str(e) or "is protected" in str(e):
                        raise
                    pass
        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][ScopeGuard] {message}[/dim]")
''',
    'legal_guard.py': '''
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
''',
    'escalation_guard.py': '''
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
''',
    'rate_guard.py': '''
import time, json, os, threading
from rich.console import Console

console = Console()

class RateGuardError(Exception):
    pass

class RateGuard:
    _windows = {}
    _lock = threading.Lock()
    DEFAULT_LIMIT = 100
    DEFAULT_WINDOW = 60.0

    @classmethod
    def validate(cls, target=None, requests=1, **kwargs):
        key = target or "global"
        now = time.time()
        limit = int(os.environ.get("NEXUS_RATE_LIMIT", cls.DEFAULT_LIMIT))
        window = float(os.environ.get("NEXUS_RATE_WINDOW", cls.DEFAULT_WINDOW))
        with cls._lock:
            ts_list = cls._windows.setdefault(key, [])
            ts_list[:] = [t for t in ts_list if now - t < window]
            ts_list.append(now)
            if len(ts_list) > limit:
                console.print(f"[red][RATE GUARD] Too many requests to {key}: {len(ts_list)} > {limit}/{window}s[/red]")
                raise RateGuardError(f"Rate limit exceeded for {key}")
        console.print(f"[green][RATE GUARD] Request allowed: {key} ({len(ts_list)}/{limit})[/green]")
        return True

    @classmethod
    def reset(cls, target=None):
        key = target or "global"
        with cls._lock:
            cls._windows.pop(key, None)

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][RateGuard] {message}[/dim]")
''',
    'audit_guard.py': '''
import json, os
from rich.console import Console

console = Console()

class AuditGuardError(Exception):
    pass

class AuditGuard:
    _log_file = os.environ.get("NEXUS_AUDIT_LOG", os.path.join(os.getcwd(), "nexus_audit.log"))

    @classmethod
    def validate(cls, action, target=None, **kwargs):
        import datetime
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "action": action,
            "target": target,
            "kwargs": {k: str(v) for k, v in kwargs.items() if k not in ("password", "secret", "key")},
        }
        try:
            with open(cls._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\\n")
            console.print(f"[dim][AuditGuard] Logged: {action} on {target}[/dim]")
        except Exception as e:
            console.print(f"[red][AuditGuard] Log failed: {e}[/red]")
        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][AuditGuard] {message}[/dim]")
''',
}

def main():
    for fname, impl in GUARDRAIL_IMPLS.items():
        path = os.path.join(GR_DIR, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(impl.strip() + "\n")
        print(f"Wrote {path}")
    print("All guardrails implemented.")

if __name__ == "__main__":
    main()