# Production-readiness roadmap

NEXUS-STRIKE is an authorised-security-assessment framework. It should be operated as a force multiplier for qualified people, not as an autonomous replacement for security review.

## Standard operating flow

1. Install the package in an isolated Python environment on Windows or Linux.
2. Configure the LLM provider and the exact approved target allow-list in `.env`.
3. Run `nexus preflight --strict` and resolve every reported item.
4. Create an engagement record using `nexus engage`; retain the written-authorisation reference.
5. Run only the approved assessment objectives.
6. Review `reports/<mission>.md` and the audit log; validate findings before remediation.

## Pre-deployment checklist

Work through this before running NEXUS-STRIKE anywhere beyond a single local
developer machine. Each item maps to a real, checkable control — this is not
aspirational.

- [ ] **`NEXUS_ENV=production`** is set. (The dashboard refuses to start
      without this AND a dashboard token — that's the point.)
- [ ] **`NEXUS_DASHBOARD_TOKEN`** is set to a high-entropy value (`openssl rand
      -hex 32`), not left blank.
- [ ] **`NEXUS_MASTER_KEY`** is set explicitly (don't rely on the
      auto-generated local key file — it isn't portable and isn't backed up).
- [ ] **At least one admin account exists**: `nexus auth create-admin`. There
      is no default account.
- [ ] **`NEXUS_ALLOWED_TARGETS`** is the exact, narrow scope for this
      engagement — not a wildcard, not left at the example default.
- [ ] **`NEXUS_LEGAL_ACK`** is set only when you actually have written
      authorization for the current engagement — it gates every scan.
- [ ] **`NEXUS_ALLOW_INSECURE_TLS`** is unset (default) unless you have a
      specific, documented reason a target's certificate must be skipped.
- [ ] **Docker deployment**: `docker-compose.yml`'s `secrets/postgres_password.txt`
      exists (copy from the `.example`, generate a real value) and `./vault`
      is a persistent bind mount, not left as an ephemeral path.
- [ ] **`requirements.lock.txt`** is what CI/Docker actually installs from,
      not the loose `>=` ranges in `pyproject.toml`.
- [ ] **CI security scans reviewed**: `bandit` and `pip-audit` run in CI as
      advisory checks (see `.github/workflows/ci.yml`) — read their output on
      the current branch before deploying, don't assume a green build means
      they found nothing (they're non-blocking by design until the existing
      codebase baseline is triaged).
- [ ] **Audit log integrity**: spot-check `AuditGuard.verify_chain()` returns
      `(True, None)` before and periodically after deployment.
- [ ] **A human reviewer** is assigned for every finding marked High or
      Critical before it drives any remediation action.
- [ ] **Named escalation contact and incident stop procedure** exist for the
      engagement (who to call, how to kill a running scan: `nexus live` scans
      launched from the dashboard can be stopped via `POST /api/scan/stop`).

## Delivery milestones

### Foundation (implemented)

- Cross-platform Python CLI.
- Explicit scope and written-authorisation gates (ScopeGuard, LegalGuard).
- Tool registry integrity verification (`nexus verify`).
- Real authentication/RBAC (`nexus/foundation/auth.py`) — no default account.
- Encrypted secrets vault (`nexus/foundation/secrets.py`).
- TLS certificate verification on by default across all tools
  (`nexus/foundation/ssl_config.py`).
- Sandboxed subprocess execution with a real, enforced tool timeout.
- Hash-chained, tamper-evident audit logging with secret redaction.
- Dashboard hardening: security headers, CSRF defense, CORS allow-list,
  path-traversal-safe report serving, production-mode token requirement.
- Deterministic Markdown/CSV/JSON/SARIF/HTML/PDF report generation from one
  normalized finding schema, with default PII/secret redaction and real
  (non-stub) attack-graph/risk-heatmap/timeline visualizations.
- Illustrative compliance control-mapping/gap-analysis tool
  (`nexus/compliance/`) — explicitly not a certification.
- Offline tests for imports, registry, scope, execution, reports, guardrails,
  auth, secrets, and dashboard hardening.

### Next engineering milestones

1. Replace generic tool templates with domain-specific, evidence-producing integrations.
2. Add signed engagement records and immutable evidence bundles (see
   `nexus/advanced/notarization.py` for an OpenTimestamps-based starting point).
3. Add provider health checks, retry policy, and circuit breakers for LLM calls.
4. Build authenticated API, cloud, source-code, and container-review connectors.
5. Promote `bandit`/`pip-audit` CI checks from advisory to blocking once the
   current codebase baseline is triaged.
6. Implement the MCP service using the official protocol before advertising it as deployable.
7. Multi-worker dashboard deployment needs a shared session store (Redis is
   already a Docker Compose service) — today's sessions are in-memory,
   single-process only; see `AuthManager`'s docstring.

## Operational requirements

- Explicit written authorization and defined testing window.
- Precise scope: domains, APIs, IP ranges, cloud accounts, and exclusions.
- Named escalation contact and incident stop procedure.
- Test accounts and test data for authenticated flows.
- A human reviewer for every finding marked High or Critical.

## Out of scope

The framework must not conduct phishing, credential theft, data exfiltration, destructive actions, availability attacks, or unauthorised exploitation. Those actions are neither required for high-quality defensive assessments nor appropriate for automated operation.
