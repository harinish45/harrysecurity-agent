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


def test_audit_redacts_sensitive_values():
    assert AuditGuard._safe_value("api_key", "value") == "[REDACTED]"
    assert AuditGuard._safe_value("payload", {"token": "value", "safe": "ok"}) == {
        "token": "[REDACTED]",
        "safe": "ok",
    }
