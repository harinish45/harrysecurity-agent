# Security Considerations

## Overview

NEXUS-STRIKE is a powerful cybersecurity platform capable of executing penetration testing tools against targets. Proper security controls must be in place to prevent misuse.

## Guardrails

All tool executions pass through 7 guardrails enforced by the `ToolExecutor`:

1. **InputGuard**: Blocks prompt injection, command injection, and path traversal in inputs
2. **ScopeGuard**: Validates target is within approved scope using hostname, wildcard, IP, or CIDR matching
3. **LegalGuard**: Requires `NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION` to be set
4. **EscalationGuard**: Requires human approval for destructive actions (exploit, RCE, SQLi)
5. **RateGuard**: Sliding-window rate limiting prevents accidental DoS on targets
6. **AuditGuard**: Append-only JSON audit log of every tool execution
7. **OutputGuard**: Prevents secret leakage (passwords, API keys, private keys) in output

## Engagement Records

Use `nexus engage` to create signed engagement records before any assessment. This creates an immutable audit trail with scope, authorization reference, and rules of engagement.

## Target Scope Enforcement

Set `NEXUS_ALLOWED_TARGETS` to restrict which targets can be scanned. Supports:
- Exact hostnames: `example.com`
- Wildcards: `*.example.com`
- IP addresses: `192.168.1.1`
- CIDR notation: `10.0.0.0/8`

## Legal Requirements

- **Written authorization is required** before scanning any target you do not own
- Set `NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION` only after obtaining written permission
- The `--engagement` flag with `nexus run` enforces scope and authorization

## Rate Limiting

- Default: 100 requests per 60-second window per target
- Configurable via `NEXUS_RATE_LIMIT_CALLS` and `NEXUS_RATE_LIMIT_WINDOW`
- Prevents accidental denial-of-service against assessment targets

## Sandboxing

- `NEXUS_SANDBOX_ENABLED=true` (default) enables sandbox mode for destructive tools
- Destructive tools require explicit escalation approval before execution

## Audit Trail

- Every tool execution is logged to `nexus_audit.log` with timestamp, action, target, and safe arguments
- Audit log is append-only to prevent tampering
- Sensitive values (passwords, tokens, API keys) are redacted automatically

## Production Deployment

1. Never run with default credentials
2. Restrict API keys using environment variables or secrets management
3. Run `nexus preflight --strict` to verify all security controls are in place
4. Use engagement records for all authorized assessments
5. Review audit logs regularly for unauthorized usage
6. Keep dependencies updated via `pip audit` or `safety check`
7. Use network isolation to prevent the tool from reaching unintended targets