import json

import pytest

from nexus.compliance.evidence_collector import (
    STATUS_EVIDENCED,
    STATUS_GAP,
    STATUS_PARTIAL,
    ComplianceEngine,
)
from nexus.foundation.guardrails.audit_guard import AuditGuard
from nexus.foundation.secrets import SecretsManager

# One representative control ID per NEXUS capability, taken from the real
# catalog (see nexus/compliance/frameworks.py).
AUDIT_CONTROL = "SOC2-CC7.1"                 # audit_log_hash_chain
RBAC_CONTROL = "SOC2-CC6.1"                  # rbac_auth
TLS_CONTROL = "SOC2-CC6.7"                   # tls_verification_by_default
VAULT_CONTROL = "SOC2-C1.1"                  # secrets_vault
REDACTION_CONTROL = "ISO27001-A.18.1.4"      # finding_redaction
RATE_CONTROL = "NIST-CSF-DE.CM-1"            # rate_limiting
SCOPE_CONTROL = "SOC2-CC6.6"                 # scope_guard_allowlist
IO_GUARD_CONTROL = "GDPR-Art25"              # input_output_guardrails
SANDBOX_CONTROL = "ISO27001-A.12.1.4"        # sandboxed_execution
TIMEOUT_CONTROL = "SOC2-A1.1"                # tool_timeout_enforcement
UNMAPPED_CONTROL = "SOC2-CC6.8"              # no NEXUS capability


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    """Point AuditGuard at a fresh temp log file and reset its hash cache,
    mirroring tests/unit/test_audit_guard.py's fixture."""
    log_file = tmp_path / "audit.log"
    monkeypatch.setattr(AuditGuard, "_log_file", str(log_file))
    monkeypatch.setattr(AuditGuard, "_last_hash", None)
    return log_file


def test_unknown_control_id_raises():
    engine = ComplianceEngine()
    with pytest.raises(KeyError):
        engine.collect_evidence("NOT-A-REAL-CONTROL")


def test_unmapped_control_is_a_gap():
    engine = ComplianceEngine()
    record = engine.collect_evidence(UNMAPPED_CONTROL)
    assert record.status == STATUS_GAP
    assert record.nexus_capability is None
    assert record.detail


# ── audit_log_hash_chain ────────────────────────────────────────────────────

def test_audit_chain_evidenced_when_intact(audit_log):
    for i in range(5):
        AuditGuard.validate(f"action.{i}", target="t", index=i)

    engine = ComplianceEngine(audit_guard=AuditGuard, audit_log_file=str(audit_log))
    record = engine.collect_evidence(AUDIT_CONTROL)
    assert record.status == STATUS_EVIDENCED
    assert record.nexus_capability == "audit_log_hash_chain"


def test_audit_chain_gap_when_tampered(audit_log):
    for i in range(5):
        AuditGuard.validate(f"action.{i}", target="t", index=i)

    lines = [line for line in audit_log.read_text(encoding="utf-8").splitlines() if line]
    tampered_index = 2
    record_json = json.loads(lines[tampered_index])
    record_json["action"] = "tampered.action"
    lines[tampered_index] = json.dumps(record_json, sort_keys=True)
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    engine = ComplianceEngine(audit_guard=AuditGuard, audit_log_file=str(audit_log))
    record = engine.collect_evidence(AUDIT_CONTROL)
    assert record.status == STATUS_GAP
    assert "line" in record.detail.lower() or str(tampered_index + 1) in record.detail


def test_audit_chain_evidenced_when_log_absent(tmp_path):
    # No log file at all -> vacuously intact (nothing to tamper with yet).
    missing = tmp_path / "does_not_exist.log"
    engine = ComplianceEngine(audit_guard=AuditGuard, audit_log_file=str(missing))
    record = engine.collect_evidence(AUDIT_CONTROL)
    assert record.status == STATUS_EVIDENCED


# ── rbac_auth ────────────────────────────────────────────────────────────

class _FakeAuthManagerNoUsers:
    def _load_users(self):
        return {}


class _FakeAuthManagerWithUser:
    def _load_users(self):
        return {"alice": {"username": "alice", "role": "admin", "is_active": True}}


def test_rbac_gap_when_no_users_configured():
    engine = ComplianceEngine(auth_manager_factory=_FakeAuthManagerNoUsers)
    record = engine.collect_evidence(RBAC_CONTROL)
    assert record.status == STATUS_GAP


def test_rbac_evidenced_when_a_user_with_role_exists():
    engine = ComplianceEngine(auth_manager_factory=_FakeAuthManagerWithUser)
    record = engine.collect_evidence(RBAC_CONTROL)
    assert record.status == STATUS_EVIDENCED


# ── tls_verification_by_default ─────────────────────────────────────────

def test_tls_evidenced_when_insecure_flag_unset(monkeypatch):
    monkeypatch.delenv("NEXUS_ALLOW_INSECURE_TLS", raising=False)
    engine = ComplianceEngine()
    record = engine.collect_evidence(TLS_CONTROL)
    assert record.status == STATUS_EVIDENCED


def test_tls_partial_when_insecure_flag_set(monkeypatch):
    monkeypatch.setenv("NEXUS_ALLOW_INSECURE_TLS", "true")
    engine = ComplianceEngine()
    record = engine.collect_evidence(TLS_CONTROL)
    assert record.status == STATUS_PARTIAL


# ── secrets_vault ────────────────────────────────────────────────────────

def test_secrets_vault_gap_when_no_key_file(tmp_path):
    factory = lambda: SecretsManager(vault_dir=tmp_path)
    engine = ComplianceEngine(secrets_manager_factory=factory)
    record = engine.collect_evidence(VAULT_CONTROL)
    assert record.status == STATUS_GAP


def test_secrets_vault_evidenced_when_key_file_present(tmp_path):
    (tmp_path / "secret.key").write_bytes(b"not-a-real-key-just-presence-check")
    factory = lambda: SecretsManager(vault_dir=tmp_path)
    engine = ComplianceEngine(secrets_manager_factory=factory)
    record = engine.collect_evidence(VAULT_CONTROL)
    assert record.status == STATUS_EVIDENCED
    # Never leak the key's content into evidence detail.
    assert "not-a-real-key-just-presence-check" not in record.detail


# ── finding_redaction (live introspection, not hardcoded) ──────────────────

def test_finding_redaction_evidenced_via_live_signature_check():
    engine = ComplianceEngine()
    record = engine.collect_evidence(REDACTION_CONTROL)
    assert record.status == STATUS_EVIDENCED
    assert record.nexus_capability == "finding_redaction"


# ── module-presence checks (rate_limiting, scope_guard_allowlist,
#    input_output_guardrails, sandboxed_execution, tool_timeout_enforcement) ──

@pytest.mark.parametrize(
    "control_id,capability",
    [
        (RATE_CONTROL, "rate_limiting"),
        (SCOPE_CONTROL, "scope_guard_allowlist"),
        (IO_GUARD_CONTROL, "input_output_guardrails"),
        (SANDBOX_CONTROL, "sandboxed_execution"),
        (TIMEOUT_CONTROL, "tool_timeout_enforcement"),
    ],
)
def test_module_presence_checks_are_real_not_fabricated(control_id, capability):
    engine = ComplianceEngine()
    record = engine.collect_evidence(control_id)
    assert record.nexus_capability == capability
    # These capabilities exist in code, so the live import check should
    # succeed, but the collector is honest that it only checked presence.
    assert record.status in (STATUS_PARTIAL, STATUS_EVIDENCED)
    assert record.detail


def test_module_presence_check_reports_gap_for_broken_import(monkeypatch):
    engine = ComplianceEngine()
    status, detail = engine._module_check("nexus.compliance.this_module_does_not_exist", None, "n/a")
    assert status == STATUS_GAP
    assert "nexus.compliance.this_module_does_not_exist" in detail


# ── collect_all ──────────────────────────────────────────────────────────

def test_collect_all_covers_every_control_in_framework():
    from nexus.compliance.frameworks import get_mappings

    engine = ComplianceEngine()
    records = engine.collect_all("SOC2")
    mappings = get_mappings("SOC2")
    assert len(records) == len(mappings)
    assert {r.control_id for r in records} == {m.control.id for m in mappings}
    for record in records:
        assert record.status in (STATUS_EVIDENCED, STATUS_PARTIAL, STATUS_GAP)
        assert record.collected_at
