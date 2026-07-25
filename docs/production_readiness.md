# Production-readiness roadmap

NEXUS-STRIKE is an authorised-security-assessment framework. It should be operated as a force multiplier for qualified people, not as an autonomous replacement for security review.

## Standard operating flow

1. Install the package in an isolated Python environment on Windows or Linux.
2. Configure the LLM provider and the exact approved target allow-list in `.env`.
3. Run `nexus preflight --strict` and resolve every reported item.
4. Create an engagement record using `nexus engage`; retain the written-authorisation reference.
5. Run only the approved assessment objectives.
6. Review `reports/<mission>.md` and the audit log; validate findings before remediation.

## Delivery milestones

### Foundation (implemented)

- Cross-platform Python CLI.
- Explicit scope and written-authorisation gates.
- Tool registry integrity verification.
- Structured audit logging with secret redaction.
- Deterministic Markdown report generation.
- Offline tests for imports, registry, scope, execution, reports, and local socket discovery.

### Next engineering milestones

1. Replace generic tool templates with domain-specific, evidence-producing integrations.
2. Add signed engagement records and immutable evidence bundles.
3. Add provider health checks, retry policy, and circuit breakers.
4. Build authenticated API, cloud, source-code, and container-review connectors.
5. Produce SARIF, JSON, and HTML reports from one normalized finding schema.
6. Add CI for Windows and Linux, dependency scanning, type checking, and linting.
7. Implement the MCP service using the official protocol before advertising it as deployable.

## Operational requirements

- Explicit written authorization and defined testing window.
- Precise scope: domains, APIs, IP ranges, cloud accounts, and exclusions.
- Named escalation contact and incident stop procedure.
- Test accounts and test data for authenticated flows.
- A human reviewer for every finding marked High or Critical.

## Out of scope

The framework must not conduct phishing, credential theft, data exfiltration, destructive actions, availability attacks, or unauthorised exploitation. Those actions are neither required for high-quality defensive assessments nor appropriate for automated operation.
