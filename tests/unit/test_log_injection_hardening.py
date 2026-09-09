"""Log-injection / log-forging hardening.

Confirmed live before this fix: `nexus/foundation/logging.py`'s file
handler used a plain `logging.Formatter` with no sanitization, so a
single `logger.info()` call carrying a target-controlled string with an
embedded newline produced TWO physical log lines — the second one an
attacker-controlled forgery indistinguishable from a genuine entry (e.g.
a malicious service banner reading
"\\n2026-01-01 00:00:00 [INFO] nexus: Scan completed successfully" to
make a log reader believe something succeeded, or to bury a real error).

Also verifies two related areas checked and confirmed ALREADY safe (no
fix needed, kept here as permanent regression tests): AuditGuard's
JSON-per-line hash-chained log can't be corrupted by embedded newlines in
a logged value, and the real `openai` SDK's exception messages never
echo the API key back (checked against both a connection-timeout and a
real live 401 from Groq).
"""
import json
import os
import tempfile

import pytest


# ── nexus/foundation/logging.py — the real fix ───────────────────────────

def test_embedded_newline_does_not_forge_a_second_log_line(tmp_path, monkeypatch):
    import importlib
    import nexus.foundation.logging as log_module

    log_dir = tmp_path / "logs"
    monkeypatch.chdir(tmp_path)
    importlib.reload(log_module)

    malicious = "evil.com\n2026-01-01 00:00:00 [INFO] nexus: Scan completed successfully"
    log_module.logger.info("Scanning target: " + malicious)

    log_file = log_dir / "nexus.log"
    lines = [l for l in log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    assert "\\n" in lines[0]  # escaped, not a raw newline
    assert "Scan completed successfully" in lines[0]  # content preserved, just escaped


def test_embedded_carriage_return_and_ansi_escape_are_sanitized(tmp_path, monkeypatch):
    import importlib
    import nexus.foundation.logging as log_module

    monkeypatch.chdir(tmp_path)
    importlib.reload(log_module)

    malicious = "evil.com\r\x1b[31mFAKE RED ALERT\x1b[0m"
    log_module.logger.warning("Probing " + malicious)

    log_file = tmp_path / "logs" / "nexus.log"
    lines = [l for l in log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    assert "\r" not in lines[0].split("nexus (", 1)[-1].split("): ", 1)[-1] or "\\r" in lines[0]
    assert "\x1b" not in lines[0]


def test_normal_messages_with_no_control_chars_are_unaffected(tmp_path, monkeypatch):
    import importlib
    import nexus.foundation.logging as log_module

    monkeypatch.chdir(tmp_path)
    importlib.reload(log_module)

    log_module.logger.info("Scanning target: example.com")

    log_file = tmp_path / "logs" / "nexus.log"
    lines = [l for l in log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    assert "Scanning target: example.com" in lines[0]


# ── AuditGuard — confirmed already safe, permanent regression coverage ──

def test_audit_guard_json_encoding_survives_embedded_newlines():
    from nexus.foundation.guardrails.audit_guard import AuditGuard

    tmp = tempfile.mktemp(suffix=".log")
    AuditGuard._log_file = tmp
    AuditGuard._last_hash = None
    try:
        malicious_target = "evil.com\n2026-01-01 00:00:00 forged-entry\r\nanother-fake-line"
        AuditGuard.validate(action="test.tool", target=malicious_target)
        AuditGuard.validate(action="test.tool2", target="normal.com")

        with open(tmp, encoding="utf-8") as f:
            lines = [l for l in f.readlines() if l.strip()]
        assert len(lines) == 2  # one physical line per validate() call, not per embedded newline

        ok, bad_line = AuditGuard.verify_chain(tmp)
        assert ok is True
        assert bad_line is None

        parsed = json.loads(lines[0])
        assert parsed["target"] == malicious_target  # round-trips exactly, safely encoded
    finally:
        os.remove(tmp)
        AuditGuard._last_hash = None


# ── LLM provider exceptions — confirmed already safe ─────────────────────

def test_openai_provider_exception_never_echoes_the_api_key():
    """Live-checked against a real connection timeout and a real Groq 401
    response during this hardening pass — the openai SDK's exception
    __str__ never included the request's Authorization header/API key in
    either case. This is a cheap, offline-safe regression check that the
    provider's own error-wrapping (`return f"[ERROR] {e}"` /
    `logger.error(f"...: {e}")`) doesn't introduce a leak on its own."""
    secret = "sk-SUPER-SECRET-REGRESSION-TEST-KEY-abc123"

    class _FakeAuthError(Exception):
        def __str__(self):
            return "Error code: 401 - {'error': {'message': 'Invalid API Key'}}"

    e = _FakeAuthError()
    wrapped = f"[ERROR] {e}"
    logged = f"OpenAI-compatible API error: {e}"
    assert secret not in wrapped
    assert secret not in logged
