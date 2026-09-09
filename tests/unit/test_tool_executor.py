import pytest

from nexus.foundation.config import config
from nexus.foundation.guardrails.audit_guard import AuditGuard
from nexus.foundation.guardrails.scope_guard import ScopeGuard, ScopeGuardError
from nexus.tools.executor import ToolExecutor
from nexus.tools.registry import tool_registry


def test_scope_guard_requires_explicit_scope(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost,127.0.0.1,::1")
    assert ScopeGuard.validate("http://localhost:8000")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("example.org")


def test_scope_guard_supports_wildcards_and_cidrs(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "*.example.test,192.0.2.0/24")
    assert ScopeGuard.validate("api.example.test")
    assert ScopeGuard.validate("192.0.2.10")


def test_executor_applies_guards_and_adds_timing(monkeypatch):
    tool_name = "test.echo"

    def echo(target: str, **kwargs):
        return {"tool": tool_name, "target": target, "status": "requires_credentials", "findings": ["ok"]}

    tool_registry.register(tool_name, echo, {"name": tool_name, "domain": "test"})
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    result = ToolExecutor().run(tool_name, "localhost")
    assert result["status"] == "requires_credentials"
    assert result["findings"][0]["title"] == "ok"
    assert result["metadata"]["execution_ms"] >= 0


def test_executor_converts_output_guard_violation_to_clean_failure(monkeypatch):
    """A tool whose output trips OutputGuard (e.g. a leaked private key)
    used to propagate a raw OutputGuardError out of ToolExecutor.run()
    instead of degrading to a truthful STATUS_FAILED result, like every
    other guardrail in this chain does — this is what surfaced as
    unhandled OutputGuardError tracebacks in prior test runs."""
    tool_name = "test.leaky"

    def leaky(target: str, **kwargs):
        return {
            "tool": tool_name, "target": target, "status": "completed",
            "findings": [{"title": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAKCAQ==\n-----END RSA PRIVATE KEY-----"}],
        }

    tool_registry.register(tool_name, leaky, {"name": tool_name, "domain": "test"})
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")

    result = ToolExecutor().run(tool_name, "localhost")

    assert result["status"] == "failed"
    assert "Output blocked" in result["error"]


def test_executor_redacts_but_preserves_legitimate_secret_findings(monkeypatch):
    """A secret-detection tool's entire purpose is to find and report an
    exposed credential ON THE TARGET (e.g. 'found an AWS key in a public
    repo') — that's a real, valuable finding, not a leak of NEXUS-STRIKE's
    own state. Before the fix, OutputGuard ran against the raw canonical
    result and wholesale discarded findings like this into STATUS_FAILED,
    silently losing the actual security finding. Now: ToolExecutor redacts
    the secret material in `evidence`/`raw` via redact_findings() first, so
    the finding (title, severity, existence) survives with only the raw
    secret value replaced by "[REDACTED]" — and that redaction marker must
    not itself re-trip OutputGuard's key=value pattern."""
    tool_name = "test.secret_finder"

    def secret_finder(target: str, **kwargs):
        return {
            "tool": tool_name, "target": target, "status": "completed",
            "findings": [{
                "title": "Exposed AWS credentials found in public repo",
                "evidence": "api_key: AKIAIOSFODNN7EXAMPLE found in config.py line 12",
                "severity": "critical",
            }],
        }

    tool_registry.register(tool_name, secret_finder, {"name": tool_name, "domain": "test"})
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")

    result = ToolExecutor().run(tool_name, "localhost")

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["title"] == "Exposed AWS credentials found in public repo"
    assert "AKIAIOSFODNN7EXAMPLE" not in finding["evidence"]
    assert "[REDACTED]" in finding["evidence"]


def test_audit_redacts_sensitive_values():
    assert AuditGuard._safe_value("api_key", "value") == "[REDACTED]"
    assert AuditGuard._safe_value("payload", {"token": "value", "safe": "ok"}) == {
        "token": "[REDACTED]",
        "safe": "ok",
    }
