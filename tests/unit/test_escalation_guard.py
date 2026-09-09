"""Behavioral tests for EscalationGuard — had zero dedicated coverage before
this session's audit found it (a) missed several clearly-destructive action
classes and (b) its ESCALATION_APPROVED override is process-wide, not
per-action (see nexus/foundation/guardrails/escalation_guard.py's own
in-code note on that second point — documented, not changed)."""
import pytest

from nexus.foundation.guardrails.escalation_guard import EscalationGuard, EscalationGuardError


def test_non_destructive_action_passes_without_approval(monkeypatch):
    monkeypatch.delenv("ESCALATION_APPROVED", raising=False)
    assert EscalationGuard.validate(tool_name="reconnaissance.dns_recon") is True


@pytest.mark.parametrize("tool_name", [
    "exploit_dev.rce_exploit",
    "offensive.credential_dump",
    "offensive.mimikatz_run",
    "offensive.kerberoast",
    "destructive.wiper",
    "network.brute_force",
    "exfil.data_exfiltration",
    "malware.backdoor_install",
    "malware.keylogger_deploy",
    "malware.ransomware_sim",
])
def test_destructive_action_blocked_without_approval(monkeypatch, tool_name):
    monkeypatch.delenv("ESCALATION_APPROVED", raising=False)
    with pytest.raises(EscalationGuardError):
        EscalationGuard.validate(tool_name=tool_name)


def test_destructive_action_allowed_with_approval(monkeypatch):
    monkeypatch.setenv("ESCALATION_APPROVED", "true")
    assert EscalationGuard.validate(tool_name="exploit_dev.rce_exploit") is True


def test_matches_on_action_kwarg_when_no_tool_name(monkeypatch):
    monkeypatch.delenv("ESCALATION_APPROVED", raising=False)
    with pytest.raises(EscalationGuardError):
        EscalationGuard.validate(action="shell_execute")
