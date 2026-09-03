"""Live evidence collection for the compliance control catalog.

For every control mapped to a real NEXUS capability, ``ComplianceEngine``
actually checks current, live NEXUS state — it does not just echo the static
mapping text from :mod:`nexus.compliance.frameworks` as if that were proof.
Where a genuinely live state check isn't practical (e.g. "is this guardrail
called on every code path"), the status is deliberately "partial" or "gap"
rather than a fabricated "evidenced".
"""
from __future__ import annotations

import importlib
import inspect
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from nexus.compliance.frameworks import get_mapping, get_mappings
from nexus.foundation.auth import AuthManager
from nexus.foundation.guardrails.audit_guard import AuditGuard
from nexus.foundation.secrets import SecretsManager

STATUS_EVIDENCED = "evidenced"
STATUS_PARTIAL = "partial"
STATUS_GAP = "gap"


@dataclass
class EvidenceRecord:
    control_id: str
    nexus_capability: Optional[str]
    status: str
    detail: str
    collected_at: str


class ComplianceEngine:
    """Collects live evidence for compliance controls.

    The audit-guard, auth-manager, and secrets-manager dependencies are
    injectable (as classes/factories) so tests can point checks at temporary
    files/vaults instead of the real ``AuditGuard``/``~/.nexus`` state.
    """

    def __init__(
        self,
        audit_guard: type[AuditGuard] = AuditGuard,
        auth_manager_factory: Callable[[], AuthManager] = AuthManager,
        secrets_manager_factory: Callable[[], SecretsManager] = SecretsManager,
        audit_log_file: Optional[str] = None,
    ) -> None:
        self._audit_guard = audit_guard
        self._auth_manager_factory = auth_manager_factory
        self._secrets_manager_factory = secrets_manager_factory
        self._audit_log_file = audit_log_file

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── public API ───────────────────────────────────────────────────────
    def collect_evidence(self, control_id: str) -> EvidenceRecord:
        mapping = get_mapping(control_id)
        if mapping is None:
            raise KeyError(f"Unknown control ID: {control_id!r}")

        capability = mapping.nexus_capability
        if capability is None:
            return EvidenceRecord(
                control_id=control_id,
                nexus_capability=None,
                status=STATUS_GAP,
                detail=f"No NEXUS capability covers this control today. {mapping.evidence_note}",
                collected_at=self._now(),
            )

        handler = getattr(self, f"_check_{capability}", None)
        if handler is None:
            return EvidenceRecord(
                control_id=control_id,
                nexus_capability=capability,
                status=STATUS_GAP,
                detail=f"Capability {capability!r} has no live evidence check implemented.",
                collected_at=self._now(),
            )

        status, detail = handler()
        return EvidenceRecord(
            control_id=control_id,
            nexus_capability=capability,
            status=status,
            detail=detail,
            collected_at=self._now(),
        )

    def collect_all(self, framework: Optional[str] = None) -> list[EvidenceRecord]:
        return [self.collect_evidence(m.control.id) for m in get_mappings(framework)]

    # ── live checks (one per NEXUS_CAPABILITIES entry) ─────────────────────
    def _check_audit_log_hash_chain(self) -> tuple[str, str]:
        ok, bad_line = self._audit_guard.verify_chain(self._audit_log_file)
        if ok:
            return STATUS_EVIDENCED, "Audit log hash chain verified intact (AuditGuard.verify_chain())."
        return STATUS_GAP, f"Audit log hash chain verification failed at line {bad_line}."

    def _check_rbac_auth(self) -> tuple[str, str]:
        try:
            users = self._auth_manager_factory()._load_users()
        except Exception as exc:  # pragma: no cover - defensive
            return STATUS_GAP, f"Could not load the user store: {exc}"

        if not users:
            return STATUS_GAP, (
                "RBAC is implemented in code (AuthManager/Role/ROLE_PERMISSIONS) but no "
                "users are configured, so it is not actually enforced yet."
            )

        with_role = [u for u in users.values() if u.get("role")]
        if with_role:
            return STATUS_EVIDENCED, f"{len(with_role)} user(s) configured with an assigned RBAC role."
        return STATUS_GAP, "Users exist in the store but none have an assigned role."

    def _check_tls_verification_by_default(self) -> tuple[str, str]:
        raw = os.environ.get("NEXUS_ALLOW_INSECURE_TLS", "")
        truthy = raw.strip().lower() in ("1", "true", "yes", "on")
        if not truthy:
            return STATUS_EVIDENCED, (
                "NEXUS_ALLOW_INSECURE_TLS is unset/false; TLS verification runs at its "
                "secure default (nexus/foundation/ssl_config.py: get_ssl_context())."
            )
        return STATUS_PARTIAL, (
            "NEXUS_ALLOW_INSECURE_TLS is currently set in this environment. This is a "
            "legitimate, bounded, explicit opt-out (private/loopback or explicit override), "
            "not a broken default, but it means TLS verification is not unconditionally on."
        )

    def _check_secrets_vault(self) -> tuple[str, str]:
        manager = self._secrets_manager_factory()
        key_path = manager._dir / manager._KEY_FILE
        if key_path.exists():
            return STATUS_EVIDENCED, (
                f"Vault key file present at {key_path} (secret VALUES are never read for "
                "this check, only key-file existence)."
            )
        return STATUS_GAP, "No vault key file found; the secrets vault has not been initialized yet."

    def _check_finding_redaction(self) -> tuple[str, str]:
        from nexus.reporting.generator import ReportGenerator

        sig = inspect.signature(ReportGenerator.generate)
        param = sig.parameters.get("redact")
        if param is not None and param.default is True:
            return STATUS_EVIDENCED, (
                "ReportGenerator.generate()'s 'redact' parameter defaults to True, wiring "
                "nexus.foundation.schema.redact_findings() into the report pipeline by "
                "default (checked live via inspect.signature, not hardcoded)."
            )
        return STATUS_GAP, (
            f"ReportGenerator.generate()'s 'redact' parameter default is "
            f"{getattr(param, 'default', 'missing')!r}, not True."
        )

    def _check_rate_limiting(self) -> tuple[str, str]:
        return self._module_check(
            "nexus.foundation.guardrails.rate_guard",
            "RateGuard",
            "Per-target/global request rate limiting exists in code (RateGuard, gated by "
            "NEXUS_RATE_LIMIT/NEXUS_RATE_WINDOW) and raises on excess; this check confirms "
            "the module imports and is not verifying every call path invokes it.",
        )

    def _check_scope_guard_allowlist(self) -> tuple[str, str]:
        return self._module_check(
            "nexus.foundation.guardrails.scope_guard",
            "ScopeGuard",
            "Target allow-list enforcement exists in code (ScopeGuard, gated by "
            "NEXUS_ALLOWED_TARGETS); this check confirms the module imports and is not "
            "verifying every tool call path enforces it.",
        )

    def _check_input_output_guardrails(self) -> tuple[str, str]:
        input_ok, input_detail = self._module_importable(
            "nexus.foundation.guardrails.input_guard", "InputGuard"
        )
        output_ok, output_detail = self._module_importable(
            "nexus.foundation.guardrails.output_guard", "OutputGuard"
        )
        if input_ok and output_ok:
            return STATUS_PARTIAL, (
                "InputGuard and OutputGuard are both present and importable; this check "
                "confirms presence, not that every tool call path routes through them."
            )
        return STATUS_GAP, f"InputGuard/OutputGuard import check failed: {input_detail or output_detail}"

    def _check_sandboxed_execution(self) -> tuple[str, str]:
        return self._module_check(
            "nexus.runtime.sandbox.docker_sandbox",
            None,
            "A Docker-based sandbox runtime exists in code for isolating tool execution; "
            "this check confirms the module imports and is not verifying every tool "
            "actually routes through it.",
        )

    def _check_tool_timeout_enforcement(self) -> tuple[str, str]:
        return self._module_check(
            "nexus.tools.executor",
            None,
            "Tool execution enforces a real wall-clock timeout (config.nexus_tool_timeout, "
            "default 300s) via a killable future in nexus/tools/executor.py; this check "
            "confirms the module imports and is not verifying the live timeout value.",
        )

    # ── helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _module_importable(module_path: str, attr: Optional[str]) -> tuple[bool, str]:
        try:
            module = importlib.import_module(module_path)
        except Exception as exc:
            return False, f"Could not import {module_path}: {exc}"
        if attr is not None and not hasattr(module, attr):
            return False, f"{module_path} imported but has no attribute {attr!r}."
        return True, ""

    def _module_check(self, module_path: str, attr: Optional[str], note: str) -> tuple[str, str]:
        ok, err = self._module_importable(module_path, attr)
        if ok:
            return STATUS_PARTIAL, note
        return STATUS_GAP, err
