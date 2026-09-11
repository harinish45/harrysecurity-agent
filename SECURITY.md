# Security Policy

## Supported Versions

We release security updates for the following versions of NEXUS-STRIKE:

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

The NEXUS-STRIKE team takes security vulnerabilities seriously. If you discover a security issue within the framework, please report it to us responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. Email the maintainer directly at: **harinishsv@gmail.com**
3. Include the following information in your report:
   - A clear description of the vulnerability.
   - Steps to reproduce the issue.
   - The affected version of NEXUS-STRIKE.
   - Any potential impact or proof-of-concept (non-destructive).

### Response SLA

- **Acknowledgment**: We will acknowledge receipt of your report within **48 hours**.
- **Triage**: We will assess the severity and validity of the report within **7 days**.
- **Resolution**: For confirmed vulnerabilities, we aim to release a patch within **30 days**, depending on complexity.
- **Disclosure**: We will coordinate with you on the public disclosure timeline. We typically request a 90-day embargo from the date of acknowledgment.

### Scope

This policy covers vulnerabilities in the NEXUS-STRIKE codebase itself. It does **not** cover:
- Vulnerabilities in third-party dependencies (please report those to the respective maintainers, though we appreciate a heads-up).
- Issues related to misconfiguration of the tool by the end-user.
- Theoretical vulnerabilities that require unrealistic preconditions.

## Safe Harbor

We support safe harbor for security researchers who:
- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our services.
- Only interact with accounts you own or with explicit permission of the account holder.
- Do not exploit the vulnerability beyond what is necessary to demonstrate the issue.

Thank you for helping keep NEXUS-STRIKE and its users safe!

## Hardening Changes (Security Pass)

A comprehensive security hardening pass replaced several previously-unimplemented
controls with real ones. If you're upgrading from an earlier checkout, read this —
some of these are breaking changes for an unauthenticated open dashboard:

- **Authentication/RBAC is now real.** `nexus/foundation/auth.py`'s `AuthManager`
  used to grant access unconditionally. There is no default account — run
  `nexus auth create-admin` to bootstrap one.
- **Secrets are now encrypted at rest.** `nexus/foundation/secrets.py`'s
  `SecretsManager` used to be a no-op. See `NEXUS_MASTER_KEY` /
  `NEXUS_VAULT_DIR` in `.env.example`.
- **TLS certificate verification is on by default everywhere.** Every tool that
  previously hardcoded `ssl.CERT_NONE` now goes through
  `nexus/foundation/ssl_config.py::get_ssl_context()`, which verifies
  certificates unless the target is private/loopback or
  `NEXUS_ALLOW_INSECURE_TLS=1` is explicitly set.
- **Production mode is a hard switch.** Set `NEXUS_ENV=production` and the
  dashboard (`web/server.py`) will refuse to start without
  `NEXUS_DASHBOARD_TOKEN` configured — **breaking change** if you were relying
  on an open local dashboard and flip this on without setting a token.
- **Dashboard hardening:** security headers (CSP, X-Frame-Options, etc.),
  same-origin-signal CSRF defense on state-changing requests, CORS is
  same-origin-only unless `NEXUS_DASHBOARD_CORS_ORIGINS` is set, path-traversal-safe
  report serving, `/ws/steer` now requires the dashboard token like `/ws/scan`
  does, and `/api/scan/start` no longer auto-injects `NEXUS_LEGAL_ACK` — it must
  already be set in the server's environment.
- **Tool execution:** a real, enforced timeout (`NEXUS_TOOL_TIMEOUT`) via a
  bounded thread pool, plus a `run_subprocess()` sandbox helper (explicit
  minimal environment, real process-tree kill on timeout) for tools that shell out.
- **Audit log is now tamper-evident:** each entry is SHA-256 hash-chained to the
  previous one; `AuditGuard.verify_chain()` detects tampering.
- **Report redaction:** `redact_findings()` strips common secret shapes
  (API keys, PEM blocks, bearer tokens, key=value credentials) from evidence
  text by default in every report exporter.

See `docs/production_readiness.md` before deploying anywhere beyond local dev.