"""Illustrative control catalog for a handful of public compliance frameworks,
mapped (where a real mapping exists) onto NEXUS-STRIKE's actual capabilities.

This is a modest, illustrative starter set (10-15 controls per framework),
not a complete reproduction of any framework's full control catalog. Control
IDs and titles follow each framework's real public numbering/structure
(SOC2 Trust Services Criteria, ISO 27001 Annex A, NIST CSF functions and
subcategories, GDPR articles, HIPAA Security Rule safeguards, PCI DSS
numbered requirements) so the mapping is meaningful, but this module should
not be mistaken for an exhaustive or authoritative copy of any framework.

NEXUS-STRIKE is a penetration-testing platform, not a GRC platform: many
controls below have no NEXUS capability that provides real evidence for
them, and are intentionally left unmapped (``nexus_capability=None``) rather
than force-fit to something that doesn't actually satisfy the control. The
gap analysis in :mod:`nexus.compliance.reports` depends on this being
honest.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

FRAMEWORKS: tuple[str, ...] = ("SOC2", "ISO27001", "NIST_CSF", "GDPR", "HIPAA", "PCI_DSS")

# The only NEXUS-STRIKE capabilities this catalog is allowed to cite as
# evidence. Every one of these corresponds to real, existing code (see the
# module docstrings referenced in each ControlMapping.evidence_note below) —
# nothing here is aspirational or planned-but-not-built.
NEXUS_CAPABILITIES: frozenset[str] = frozenset({
    "audit_log_hash_chain",       # nexus/foundation/guardrails/audit_guard.py
    "rbac_auth",                  # nexus/foundation/auth.py
    "tls_verification_by_default",  # nexus/foundation/ssl_config.py
    "secrets_vault",              # nexus/foundation/secrets.py
    "finding_redaction",          # nexus/foundation/schema.py: redact_findings()
    "rate_limiting",              # nexus/foundation/guardrails/rate_guard.py
    "scope_guard_allowlist",      # nexus/foundation/guardrails/scope_guard.py
    "input_output_guardrails",    # nexus/foundation/guardrails/{input,output}_guard.py
    "sandboxed_execution",        # nexus/runtime/sandbox/docker_sandbox.py
    "tool_timeout_enforcement",   # nexus/tools/executor.py
})


@dataclass(frozen=True)
class Control:
    id: str
    framework: str
    title: str
    description: str

    def __post_init__(self) -> None:
        if self.framework not in FRAMEWORKS:
            raise ValueError(f"Unknown framework {self.framework!r} for control {self.id!r}")


@dataclass(frozen=True)
class ControlMapping:
    control: Control
    nexus_capability: Optional[str]   # None means: no NEXUS capability covers this control today
    evidence_note: str                # how the capability satisfies it, or why it's a gap

    def __post_init__(self) -> None:
        if self.nexus_capability is not None and self.nexus_capability not in NEXUS_CAPABILITIES:
            raise ValueError(
                f"ControlMapping for {self.control.id!r} references unknown capability "
                f"{self.nexus_capability!r}"
            )


def _c(control_id: str, framework: str, title: str, description: str) -> Control:
    return Control(id=control_id, framework=framework, title=title, description=description)


def _m(control: Control, capability: Optional[str], note: str) -> ControlMapping:
    return ControlMapping(control=control, nexus_capability=capability, evidence_note=note)


# ── SOC 2 (Trust Services Criteria) ─────────────────────────────────────────
_SOC2 = [
    _m(_c("SOC2-CC6.1", "SOC2", "Logical access security",
          "The entity implements logical access security software, infrastructure, and "
          "architectures to protect information assets from unauthorized access."),
       "rbac_auth",
       "AuthManager enforces password + optional-TOTP authentication and role-based "
       "permissions (Role/Permission/ROLE_PERMISSIONS) before any protected action."),
    _m(_c("SOC2-CC6.2", "SOC2", "Prior-to-issuance access authorization",
          "Prior to issuing system credentials, the entity registers and authorizes new "
          "internal and external users."),
       "rbac_auth",
       "AuthManager.register_user() creates accounts with an explicit Role; there is no "
       "credential issuance path that bypasses this."),
    _m(_c("SOC2-CC6.3", "SOC2", "Role-based access removal and modification",
          "The entity authorizes, modifies, or removes access based on roles, "
          "responsibilities, or the system design and changes."),
       "rbac_auth",
       "Roles are enumerated centrally (Role enum, ROLE_PERMISSIONS) and account state "
       "(is_active, role) is stored per-user, so access can be revoked by deactivation."),
    _m(_c("SOC2-CC6.6", "SOC2", "Boundary protection against external threats",
          "The entity implements logical access security measures to protect against "
          "threats from sources outside its system boundaries."),
       "scope_guard_allowlist",
       "ScopeGuard rejects any target not explicitly present in NEXUS_ALLOWED_TARGETS, "
       "bounding what the platform will ever act against."),
    _m(_c("SOC2-CC6.7", "SOC2", "Restricted transmission and movement of information",
          "The entity restricts the transmission, movement, and removal of information to "
          "authorized users and processes."),
       "tls_verification_by_default",
       "get_ssl_context() enforces TLS verification by default for outbound connections; "
       "insecure TLS requires an explicit, logged opt-out."),
    _m(_c("SOC2-CC6.8", "SOC2", "Malicious software prevention",
          "The entity implements controls to prevent or detect and act upon the "
          "introduction of unauthorized or malicious software."),
       None,
       "NEXUS has no endpoint/malware-prevention control of its own; it is a testing "
       "platform, not an EDR. Gap."),
    _m(_c("SOC2-CC7.1", "SOC2", "Detection of configuration changes",
          "The entity uses detection and monitoring procedures to identify changes to "
          "configurations that introduce new vulnerabilities."),
       "audit_log_hash_chain",
       "Every guarded action is appended to a hash-chained audit log (AuditGuard.validate); "
       "tampering with a past entry breaks the chain and is detectable via verify_chain()."),
    _m(_c("SOC2-CC7.2", "SOC2", "Security event monitoring",
          "The entity monitors system components for anomalies indicative of malicious "
          "acts, natural disasters, or errors."),
       None,
       "No SIEM/anomaly-detection capability exists in NEXUS today. Gap."),
    _m(_c("SOC2-CC7.3", "SOC2", "Security incident evaluation",
          "The entity evaluates security events to determine whether they could or have "
          "resulted in a failure to meet objectives (a security incident)."),
       None,
       "No incident-triage workflow exists in NEXUS. Gap."),
    _m(_c("SOC2-CC7.4", "SOC2", "Incident response",
          "The entity responds to identified security incidents by executing a defined "
          "incident response program."),
       None,
       "No incident response program is implemented in NEXUS. Gap."),
    _m(_c("SOC2-CC8.1", "SOC2", "Change management",
          "The entity authorizes, designs, develops, configures, documents, tests, "
          "approves, and implements changes to infrastructure, data, and software."),
       None,
       "Change management is a process/organizational control outside NEXUS's scope. Gap."),
    _m(_c("SOC2-CC9.2", "SOC2", "Vendor and third-party risk management",
          "The entity assesses and manages risks associated with vendors and business "
          "partners."),
       None,
       "No vendor risk management capability exists in NEXUS. Gap."),
    _m(_c("SOC2-P1.1", "SOC2", "Privacy notice to data subjects",
          "The entity provides notice to data subjects about its privacy practices."),
       None,
       "Privacy notice is an organizational/legal artifact, not a software control. Gap."),
    _m(_c("SOC2-C1.1", "SOC2", "Identification and protection of confidential information",
          "The entity identifies and maintains confidential information to meet its "
          "objectives related to confidentiality."),
       "secrets_vault",
       "SecretsManager stores credentials/API keys encrypted at rest (Fernet) under a "
       "master key, rather than in plaintext configuration."),
    _m(_c("SOC2-A1.2", "SOC2", "Environmental protections and recovery infrastructure",
          "The entity authorizes, designs, develops, implements, operates, approves, "
          "maintains, and monitors environmental protections, backup, and recovery "
          "infrastructure."),
       None,
       "No backup/DR infrastructure is implemented by NEXUS itself. Gap."),
    _m(_c("SOC2-A1.1", "SOC2", "Capacity and availability management",
          "The entity maintains, monitors, and evaluates current processing capacity and "
          "use of system components to manage capacity demand and enable the "
          "implementation of additional capacity to help meet its objectives."),
       "tool_timeout_enforcement",
       "nexus/tools/executor.py enforces a real wall-clock timeout on every tool "
       "execution (config.nexus_tool_timeout, default 300s) via a killable future, "
       "preventing a single hung tool run from exhausting execution capacity "
       "indefinitely."),
]

# ── ISO/IEC 27001:2013 (Annex A) ────────────────────────────────────────────
_ISO27001 = [
    _m(_c("ISO27001-A.9.1.1", "ISO27001", "Access control policy",
          "An access control policy shall be established, documented and reviewed based "
          "on business and information security requirements."),
       "rbac_auth",
       "Role/Permission/ROLE_PERMISSIONS in nexus/foundation/auth.py encode a concrete, "
       "enforced access control policy (admin/operator/analyst/viewer)."),
    _m(_c("ISO27001-A.9.2.1", "ISO27001", "User registration and de-registration",
          "A formal user registration and de-registration process shall be implemented to "
          "enable assignment of access rights."),
       "rbac_auth",
       "AuthManager.register_user() creates accounts; is_active=False de-registers them "
       "without deleting audit history."),
    _m(_c("ISO27001-A.9.2.3", "ISO27001", "Management of privileged access rights",
          "The allocation and use of privileged access rights shall be restricted and "
          "controlled."),
       "rbac_auth",
       "Role.ADMIN is the only role granted the full Permission set (frozenset(Permission)); "
       "all other roles are explicitly scoped down."),
    _m(_c("ISO27001-A.9.4.2", "ISO27001", "Secure log-on procedures",
          "Access to systems and applications shall be controlled by a secure log-on "
          "procedure."),
       "rbac_auth",
       "AuthManager.authenticate() enforces bcrypt password verification, account lockout "
       "after MAX_FAILED_ATTEMPTS, and optional TOTP 2FA before issuing a session."),
    _m(_c("ISO27001-A.10.1.1", "ISO27001", "Policy on the use of cryptographic controls",
          "A policy on the use of cryptographic controls for protection of information "
          "shall be developed and implemented."),
       "secrets_vault",
       "SecretsManager encrypts stored secrets at rest with Fernet (AES-128-CBC + HMAC) "
       "under a master key from NEXUS_MASTER_KEY or a locally generated, file-permission-"
       "restricted key."),
    _m(_c("ISO27001-A.12.4.1", "ISO27001", "Event logging",
          "Event logs recording user activities, exceptions, faults and information "
          "security events shall be produced, kept and regularly reviewed."),
       "audit_log_hash_chain",
       "AuditGuard.validate() writes a structured, timestamped entry for every guarded "
       "action to the audit log."),
    _m(_c("ISO27001-A.12.4.2", "ISO27001", "Protection of log information",
          "Logging facilities and log information shall be protected against tampering "
          "and unauthorized access."),
       "audit_log_hash_chain",
       "Each audit entry embeds a SHA-256 hash chained to the previous entry; "
       "AuditGuard.verify_chain() detects any tampering with past entries."),
    _m(_c("ISO27001-A.12.4.3", "ISO27001", "Administrator and operator logs",
          "System administrator and operator activities shall be logged and the logs "
          "protected and regularly reviewed."),
       "audit_log_hash_chain",
       "Audit entries capture the action and target for every guarded operation "
       "regardless of the acting role; the hash chain protects them post-hoc."),
    _m(_c("ISO27001-A.13.1.1", "ISO27001", "Network controls",
          "Networks shall be managed and controlled to protect information in systems and "
          "applications."),
       "scope_guard_allowlist",
       "ScopeGuard restricts which hosts/URLs NEXUS will ever act against to an explicit "
       "engagement allow-list (NEXUS_ALLOWED_TARGETS)."),
    _m(_c("ISO27001-A.13.2.1", "ISO27001", "Information transfer policies and procedures",
          "Formal transfer policies, procedures and controls shall be in place to protect "
          "the transfer of information."),
       "tls_verification_by_default",
       "get_ssl_context() verifies TLS by default for outbound transfers; insecure TLS is "
       "opt-in and bounded to private/loopback or explicit override."),
    _m(_c("ISO27001-A.14.2.8", "ISO27001", "System security testing",
          "Testing of security functionality shall be carried out during development."),
       None,
       "No automated security-functionality test harness for NEXUS's own code is exposed "
       "as a capability here (the project has a test suite, but that is not a compliance "
       "capability this catalog can cite as live evidence). Gap."),
    _m(_c("ISO27001-A.16.1.2", "ISO27001", "Reporting information security events",
          "Information security events shall be reported through appropriate management "
          "channels as quickly as possible."),
       None,
       "No incident-reporting workflow exists in NEXUS. Gap."),
    _m(_c("ISO27001-A.18.1.3", "ISO27001", "Protection of records",
          "Records shall be protected from loss, destruction, falsification, unauthorized "
          "access and unauthorized release."),
       "audit_log_hash_chain",
       "The hash chain makes falsification of past audit records detectable; it does not "
       "by itself prevent loss or unauthorized access to the log file."),
    _m(_c("ISO27001-A.18.1.4", "ISO27001", "Privacy and protection of PII",
          "Privacy and protection of personally identifiable information shall be ensured "
          "as required in relevant legislation."),
       "finding_redaction",
       "redact_findings() strips secret- and credential-shaped text from finding evidence "
       "before it leaves the system via any exporter or report."),
    _m(_c("ISO27001-A.12.1.4", "ISO27001", "Separation of environments",
          "Development, testing, and operational environments shall be separated to "
          "reduce risks of unauthorized access or changes."),
       "sandboxed_execution",
       "nexus/runtime/sandbox/docker_sandbox.py provides container-isolated execution, "
       "separating tool run environments from the host running NEXUS."),
]

# ── NIST Cybersecurity Framework (functions/subcategories) ─────────────────
_NIST_CSF = [
    _m(_c("NIST-CSF-ID.AM-1", "NIST_CSF", "Physical devices and systems inventoried",
          "Physical devices and systems within the organization are inventoried."),
       None,
       "NEXUS does not perform asset inventory of the organization running it. Gap."),
    _m(_c("NIST-CSF-ID.GV-3", "NIST_CSF", "Legal and regulatory requirements understood",
          "Legal and regulatory requirements regarding cybersecurity, including privacy "
          "and civil liberties obligations, are understood and managed."),
       None,
       "This is an organizational/legal control; NEXUS provides no capability for it. Gap."),
    _m(_c("NIST-CSF-PR.AC-1", "NIST_CSF", "Identities and credentials managed",
          "Identities and credentials are issued, managed, verified, revoked, and audited "
          "for authorized devices, users and processes."),
       "rbac_auth",
       "AuthManager issues, verifies (bcrypt + optional TOTP), and can deactivate "
       "credentials; every user record is stored with an audit trail via created_at."),
    _m(_c("NIST-CSF-PR.AC-4", "NIST_CSF", "Access permissions managed (least privilege)",
          "Access permissions and authorizations are managed, incorporating the "
          "principles of least privilege and separation of duties."),
       "rbac_auth",
       "ROLE_PERMISSIONS scopes each of the four roles to the minimum permission set it "
       "needs; VIEWER, for example, has read-only report access only."),
    _m(_c("NIST-CSF-PR.AC-5", "NIST_CSF", "Network integrity protected",
          "Network integrity is protected, incorporating network segregation where "
          "appropriate."),
       "scope_guard_allowlist",
       "ScopeGuard prevents NEXUS from taking action against any target outside an "
       "explicit allow-list, bounding its network footprint."),
    _m(_c("NIST-CSF-PR.DS-1", "NIST_CSF", "Data-at-rest protected",
          "Data-at-rest is protected."),
       "secrets_vault",
       "SecretsManager encrypts stored secrets at rest with Fernet under a master key."),
    _m(_c("NIST-CSF-PR.DS-2", "NIST_CSF", "Data-in-transit protected",
          "Data-in-transit is protected."),
       "tls_verification_by_default",
       "get_ssl_context() enforces certificate verification for outbound TLS connections "
       "by default."),
    _m(_c("NIST-CSF-PR.PT-1", "NIST_CSF", "Audit/log records determined and implemented",
          "Audit/log records are determined, documented, implemented, and reviewed in "
          "accordance with policy."),
       "audit_log_hash_chain",
       "AuditGuard.validate() writes structured audit entries; verify_chain() supports "
       "review/integrity-checking of the resulting log."),
    _m(_c("NIST-CSF-PR.PT-3", "NIST_CSF", "Least functionality principle applied",
          "The principle of least functionality is incorporated by configuring systems to "
          "provide only essential capabilities."),
       "sandboxed_execution",
       "Container-isolated tool execution (docker_sandbox.py) limits what a running tool "
       "can reach or do relative to the host."),
    _m(_c("NIST-CSF-DE.CM-1", "NIST_CSF", "Network monitored for potential events",
          "The network is monitored to detect potential cybersecurity events."),
       "rate_limiting",
       "RateGuard tracks and bounds request volume per target/global window, and raises "
       "on excess, which is the closest live signal NEXUS produces to this control."),
    _m(_c("NIST-CSF-DE.CM-7", "NIST_CSF", "Monitoring for unauthorized personnel/connections",
          "Monitoring for unauthorized personnel, connections, devices, and software is "
          "performed."),
       None,
       "No host/network-level unauthorized-access monitoring exists in NEXUS itself. Gap."),
    _m(_c("NIST-CSF-DE.AE-3", "NIST_CSF", "Event data collected and correlated",
          "Event data are collected and correlated from multiple sources and sensors."),
       "audit_log_hash_chain",
       "The audit log aggregates guarded-action events from across NEXUS's guardrails "
       "into a single ordered, chained record."),
    _m(_c("NIST-CSF-RS.RP-1", "NIST_CSF", "Response plan executed",
          "Response plan is executed during or after an incident."),
       None,
       "No incident response plan/automation exists in NEXUS. Gap."),
    _m(_c("NIST-CSF-RS.CO-2", "NIST_CSF", "Incidents reported consistent with criteria",
          "Incidents are reported consistent with established criteria."),
       None,
       "No incident reporting workflow exists in NEXUS. Gap."),
    _m(_c("NIST-CSF-RC.RP-1", "NIST_CSF", "Recovery plan executed",
          "Recovery plan is executed during or after a cybersecurity incident."),
       None,
       "No recovery/DR capability exists in NEXUS itself. Gap."),
]

# ── GDPR (selected articles) ────────────────────────────────────────────────
_GDPR = [
    _m(_c("GDPR-Art5", "GDPR", "Principles relating to processing of personal data",
          "Personal data shall be processed lawfully, fairly, transparently, and with "
          "purpose/storage limitation and data minimisation."),
       None,
       "Lawful-basis and data-minimisation are organizational/legal determinations NEXUS "
       "cannot attest to on its own. Gap."),
    _m(_c("GDPR-Art25", "GDPR", "Data protection by design and by default",
          "The controller shall implement appropriate technical and organisational "
          "measures to implement data-protection principles by design and by default."),
       "input_output_guardrails",
       "InputGuard/OutputGuard inspect tool input/output for secret- and injection-shaped "
       "content before it is acted on or returned, a concrete by-design technical measure."),
    _m(_c("GDPR-Art30", "GDPR", "Records of processing activities",
          "Each controller shall maintain a record of processing activities under its "
          "responsibility."),
       "audit_log_hash_chain",
       "The hash-chained audit log records what actions were taken against which targets "
       "and when, though it is not itself a full Art. 30 processing register."),
    _m(_c("GDPR-Art32-storage", "GDPR", "Security of processing — encryption",
          "The controller and processor shall implement appropriate technical measures "
          "including, as appropriate, the encryption of personal data."),
       "secrets_vault",
       "SecretsManager encrypts stored credentials/secrets at rest with Fernet."),
    _m(_c("GDPR-Art32-transit", "GDPR", "Security of processing — confidentiality in transit",
          "Technical measures shall ensure ongoing confidentiality of processing systems, "
          "including data in transit."),
       "tls_verification_by_default",
       "get_ssl_context() verifies TLS by default for outbound connections carrying data."),
    _m(_c("GDPR-Art33", "GDPR", "Notification of a breach to the supervisory authority",
          "The controller shall notify a personal data breach to the supervisory "
          "authority within 72 hours."),
       None,
       "No breach-notification workflow exists in NEXUS. Gap."),
    _m(_c("GDPR-Art34", "GDPR", "Communication of a breach to the data subject",
          "The controller shall communicate a personal data breach to the data subject "
          "when it is likely to result in a high risk."),
       None,
       "No breach-communication workflow exists in NEXUS. Gap."),
    _m(_c("GDPR-Art35", "GDPR", "Data protection impact assessment",
          "Where processing is likely to result in high risk, the controller shall carry "
          "out a DPIA prior to processing."),
       None,
       "DPIA is an organizational assessment process outside NEXUS's scope. Gap."),
    _m(_c("GDPR-Art17", "GDPR", "Right to erasure",
          "The data subject shall have the right to obtain erasure of personal data "
          "concerning them without undue delay."),
       None,
       "NEXUS has no per-data-subject erasure workflow for its own stored data. Gap."),
    _m(_c("GDPR-Art15", "GDPR", "Right of access by the data subject",
          "The data subject shall have the right to obtain confirmation and access to "
          "their personal data being processed."),
       None,
       "No data-subject access request workflow exists in NEXUS. Gap."),
    _m(_c("GDPR-Art9", "GDPR", "Processing of special categories of personal data",
          "Processing of special categories of personal data is prohibited subject to "
          "specific exceptions and safeguards."),
       "finding_redaction",
       "redact_findings() strips secret/credential-shaped values out of finding evidence "
       "before export; it reduces incidental exposure of sensitive scraped data but is not "
       "a full special-category-data control."),
    _m(_c("GDPR-Art28", "GDPR", "Processor obligations",
          "Processing by a processor shall be governed by a contract binding the "
          "processor to the controller's instructions."),
       None,
       "Processor contract terms are a legal/organizational matter outside NEXUS's scope. "
       "Gap."),
    _m(_c("GDPR-Art24", "GDPR", "Responsibility of the controller",
          "The controller shall implement appropriate technical and organisational "
          "measures to ensure and demonstrate that processing complies with the "
          "Regulation."),
       "rbac_auth",
       "Role-based access control is one concrete technical measure demonstrating "
       "restricted processing access, though it does not by itself demonstrate full "
       "compliance."),
    _m(_c("GDPR-Art5-1f", "GDPR", "Integrity and confidentiality",
          "Personal data shall be processed in a manner that ensures appropriate security, "
          "including protection against unauthorised or unlawful processing and against "
          "accidental loss, destruction or damage."),
       "audit_log_hash_chain",
       "The hash chain makes unauthorized post-hoc modification of processing records "
       "detectable (AuditGuard.verify_chain())."),
]

# ── HIPAA Security Rule (selected safeguards) ───────────────────────────────
_HIPAA = [
    _m(_c("HIPAA-164.312(a)(1)", "HIPAA", "Access control",
          "Implement technical policies and procedures that allow access only to those "
          "persons or software programs that have been granted access rights."),
       "rbac_auth",
       "AuthManager gates every protected action on an authenticated session and "
       "role-based permission check (has_permission/require_permission)."),
    _m(_c("HIPAA-164.312(a)(2)(i)", "HIPAA", "Unique user identification",
          "Assign a unique name and/or number for identifying and tracking user "
          "identity."),
       "rbac_auth",
       "Each User has a unique user_id (secrets.token_urlsafe) and username; sessions are "
       "tied to that identity."),
    _m(_c("HIPAA-164.312(a)(2)(iv)", "HIPAA", "Encryption and decryption",
          "Implement a mechanism to encrypt and decrypt electronic protected health "
          "information."),
       "secrets_vault",
       "SecretsManager provides authenticated encryption (Fernet) for secrets at rest; "
       "NEXUS itself does not process PHI, but this is the encryption mechanism available."),
    _m(_c("HIPAA-164.312(b)", "HIPAA", "Audit controls",
          "Implement hardware, software, and/or procedural mechanisms that record and "
          "examine activity in information systems that contain or use PHI."),
       "audit_log_hash_chain",
       "AuditGuard records every guarded action with a tamper-evident hash chain, "
       "verifiable via verify_chain()."),
    _m(_c("HIPAA-164.312(c)(1)", "HIPAA", "Integrity",
          "Implement policies and procedures to protect information from improper "
          "alteration or destruction."),
       "audit_log_hash_chain",
       "The SHA-256 hash chain over audit entries makes improper alteration of past "
       "records detectable."),
    _m(_c("HIPAA-164.312(d)", "HIPAA", "Person or entity authentication",
          "Implement procedures to verify that a person or entity seeking access is the "
          "one claimed."),
       "rbac_auth",
       "AuthManager.authenticate() verifies a bcrypt password hash and, when enabled, a "
       "TOTP second factor, before issuing a session."),
    _m(_c("HIPAA-164.312(e)(1)", "HIPAA", "Transmission security",
          "Implement technical security measures to guard against unauthorized access to "
          "electronic PHI transmitted over a network."),
       "tls_verification_by_default",
       "get_ssl_context() enforces TLS certificate verification by default for outbound "
       "network transmissions."),
    _m(_c("HIPAA-164.308(a)(1)(ii)(D)", "HIPAA", "Information system activity review",
          "Implement procedures to regularly review records of information system "
          "activity, such as audit logs."),
       "audit_log_hash_chain",
       "The audit log is a reviewable, ordered record of activity; verify_chain() lets a "
       "reviewer confirm it has not been altered since it was written."),
    _m(_c("HIPAA-164.308(a)(3)", "HIPAA", "Workforce security",
          "Implement policies and procedures to ensure that workforce members have "
          "appropriate access, and to prevent access by those who should not have it."),
       None,
       "Workforce policy/HR process is outside NEXUS's scope; RBAC enforces access once "
       "an account exists, but who receives an account is an organizational decision. Gap."),
    _m(_c("HIPAA-164.308(a)(4)", "HIPAA", "Information access management",
          "Implement policies and procedures for authorizing access to electronic PHI "
          "consistent with the access control requirements."),
       "rbac_auth",
       "Access is authorized per-role via ROLE_PERMISSIONS at the point every protected "
       "action is attempted."),
    _m(_c("HIPAA-164.308(a)(5)", "HIPAA", "Security awareness and training",
          "Implement a security awareness and training program for all workforce "
          "members."),
       None,
       "Training is an organizational program NEXUS provides no capability for. Gap."),
    _m(_c("HIPAA-164.308(a)(6)", "HIPAA", "Security incident procedures",
          "Implement policies and procedures to address security incidents."),
       None,
       "No incident response workflow exists in NEXUS. Gap."),
    _m(_c("HIPAA-164.308(a)(7)", "HIPAA", "Contingency plan",
          "Establish policies and procedures for responding to an emergency or other "
          "occurrence that damages systems containing electronic PHI."),
       None,
       "No backup/contingency capability exists in NEXUS itself. Gap."),
    _m(_c("HIPAA-164.310(d)(1)", "HIPAA", "Device and media controls",
          "Implement policies and procedures that govern the receipt and removal of "
          "hardware and electronic media containing electronic PHI."),
       None,
       "Physical media control is outside the scope of a software platform like NEXUS. "
       "Gap."),
    _m(_c("HIPAA-164.514(b)", "HIPAA", "De-identification of PHI",
          "Implement de-identification methods so that information does not identify an "
          "individual."),
       "finding_redaction",
       "redact_findings() strips secret- and credential-shaped values out of scan "
       "evidence before export; it is a redaction control, not a full HIPAA "
       "de-identification (Safe Harbor/expert determination) method."),
]

# ── PCI DSS (selected numbered requirements, v4.0-style numbering) ─────────
_PCI_DSS = [
    _m(_c("PCI_DSS-1.2", "PCI_DSS", "Network security controls configured and maintained",
          "Network security controls (NSCs) are configured and maintained to restrict "
          "connections between untrusted and trusted networks."),
       "scope_guard_allowlist",
       "ScopeGuard restricts NEXUS's own outbound targeting to an explicit allow-list, "
       "the closest analogue NEXUS has to a network security control it enforces on "
       "itself."),
    _m(_c("PCI_DSS-2.2", "PCI_DSS", "System components configured securely",
          "Configuration standards are developed, implemented, and maintained to secure "
          "system components."),
       None,
       "Secure-configuration baselining of the deployment environment is outside NEXUS's "
       "scope as a testing tool. Gap."),
    _m(_c("PCI_DSS-3.5", "PCI_DSS", "Cryptographic keys protecting stored account data",
          "Cryptographic keys used to protect stored account data are secured against "
          "disclosure and misuse."),
       "secrets_vault",
       "SecretsManager derives/stores the master key with restrictive file permissions "
       "(0600 best-effort) and supports rotation via rotate_key()."),
    _m(_c("PCI_DSS-4.2", "PCI_DSS", "Strong cryptography for PAN in transit",
          "PAN is protected with strong cryptography during transmission over open, "
          "public networks."),
       "tls_verification_by_default",
       "get_ssl_context() enforces certificate-verified TLS by default for outbound "
       "transmissions."),
    _m(_c("PCI_DSS-6.2", "PCI_DSS", "Bespoke and custom software developed securely",
          "Bespoke and custom software is developed securely, based on secure software "
          "development practices."),
       "input_output_guardrails",
       "InputGuard/OutputGuard validate tool input and filter tool output for "
          "injection/secret-shaped content as a runtime secure-development control."),
    _m(_c("PCI_DSS-6.5", "PCI_DSS", "Common coding vulnerabilities addressed",
          "Software engineering techniques address common vulnerabilities in the "
          "software development process."),
       "input_output_guardrails",
       "InputGuard blocks homoglyph/zero-width obfuscation and high-entropy payloads in "
       "tool input; OutputGuard blocks secret/credential and command-injection-shaped "
       "output."),
    _m(_c("PCI_DSS-7.2", "PCI_DSS", "Access appropriately defined and assigned",
          "An access control model restricts access to system components and data based "
          "on job classification and function (least privilege)."),
       "rbac_auth",
       "ROLE_PERMISSIONS assigns each role the minimum permission set for its function."),
    _m(_c("PCI_DSS-8.2", "PCI_DSS", "User identification and authentication managed",
          "User identification and related accounts for users are managed."),
       "rbac_auth",
       "AuthManager manages unique accounts (register_user/get_user) with lockout after "
       "MAX_FAILED_ATTEMPTS failed logins."),
    _m(_c("PCI_DSS-8.4", "PCI_DSS", "Multi-factor authentication implemented",
          "Multi-factor authentication is implemented to secure access into the "
          "cardholder data environment."),
       "rbac_auth",
       "AuthManager supports TOTP-based 2FA (enable_totp) as an optional second factor; "
       "note it is opt-in per user, not mandatory, so this control is only partially "
       "satisfied at the live-evidence layer for accounts without 2FA enabled."),
    _m(_c("PCI_DSS-10.2", "PCI_DSS", "Audit logs support detection of anomalies",
          "Audit logs are implemented to support the detection of anomalies and "
          "suspicious activity."),
       "audit_log_hash_chain",
       "AuditGuard.validate() logs every guarded action, target, and timestamp."),
    _m(_c("PCI_DSS-10.3", "PCI_DSS", "Audit logs protected from destruction/modification",
          "Audit log history is retained and protected from destruction and unauthorized "
          "modification."),
       "audit_log_hash_chain",
       "The SHA-256 hash chain over log entries makes unauthorized modification of "
       "history detectable (verify_chain())."),
    _m(_c("PCI_DSS-11.4", "PCI_DSS", "Penetration testing performed",
          "External and internal penetration testing is regularly performed."),
       None,
       "NEXUS is a tool used to perform penetration testing against a target; it has no "
       "capability that provides evidence NEXUS's own environment was tested. Gap."),
    _m(_c("PCI_DSS-12.10", "PCI_DSS", "Incident response plan ready",
          "An incident response plan exists and is ready to be activated."),
       None,
       "No incident response plan/capability exists in NEXUS. Gap."),
    _m(_c("PCI_DSS-1.4", "PCI_DSS", "Controls against excessive/anomalous traffic",
          "Network security controls limit excessive or anomalous traffic patterns "
          "between environments."),
       "rate_limiting",
       "RateGuard enforces a configurable request-rate ceiling per target/global window "
       "and raises on excess."),
    _m(_c("PCI_DSS-6.3", "PCI_DSS", "Vulnerabilities identified and addressed before release",
          "Security vulnerabilities are identified and addressed, including testing "
          "changes before they are deployed into production."),
       "sandboxed_execution",
       "Container-isolated execution (docker_sandbox.py) lets potentially risky tool "
       "behavior run isolated from the host before results are trusted."),
]

ALL_MAPPINGS: list[ControlMapping] = (
    _SOC2 + _ISO27001 + _NIST_CSF + _GDPR + _HIPAA + _PCI_DSS
)

_ids = [m.control.id for m in ALL_MAPPINGS]
_dupes = {cid for cid in _ids if _ids.count(cid) > 1}
if _dupes:
    raise RuntimeError(f"Duplicate control IDs in compliance catalog: {sorted(_dupes)}")

_BY_ID: dict[str, ControlMapping] = {m.control.id: m for m in ALL_MAPPINGS}


def get_mappings(framework: str | None = None) -> list[ControlMapping]:
    """Return all control mappings, optionally filtered to one framework."""
    if framework is None:
        return list(ALL_MAPPINGS)
    if framework not in FRAMEWORKS:
        raise ValueError(f"Unknown framework {framework!r}; expected one of {FRAMEWORKS}")
    return [m for m in ALL_MAPPINGS if m.control.framework == framework]


def get_mapping(control_id: str) -> ControlMapping | None:
    """Return the ControlMapping for a single control ID, or None if unknown."""
    return _BY_ID.get(control_id)


def unmapped_controls(framework: str | None = None) -> list[Control]:
    """Controls with no NEXUS capability behind them (an honest gap list)."""
    return [m.control for m in get_mappings(framework) if m.nexus_capability is None]
