# NEXUS-STRIKE v1.0.0 Release Notes

**Release date:** 2026-08-12
**Version:** 1.0.0
**Branch:** release/v1.0.0
**Status:** Production/Stable

---

## 🎉 What's New in v1.0

NEXUS-STRIKE v1.0.0 is the first **production-grade** release of the Ultimate AI-Powered Cybersecurity Platform. This release ships 5 new real security tools, a revamped web dashboard with real-time progress, a skills CLI, and full distribution polish — all in one cohesive package.

---

## 🚀 5 New Real Security Tools

### 1. `reconnaissance.subdomain_takeover`
Detects subdomain takeover vulnerabilities by analyzing DNS CNAME records against 15+ known-vulnerable service fingerprints: AWS S3, CloudFront, GitHub Pages, Heroku, Azure, Pantheon, Tumblr, Shopify, Fastly, Bitbucket, Surge.sh, Netlify, ReadTheDocs, Zendesk, and Ghost.

### 2. `webapp.jwt_attacks`
A complete JWT attack suite:
- `alg=none` authentication bypass
- RS256 → HS256 algorithm confusion
- `kid` header injection
- Weak HMAC secret brute force (top common secrets)
- Payload privilege escalation

### 3. `webapi.graphql_attacks`
GraphQL security scanner:
- Introspection query detection
- Query depth limit enforcement testing (DoS prevention)
- Batching/alias abuse detection (brute-force amplification)

### 4. `webapi.oauth_audit`
OAuth/OIDC misconfiguration auditor:
- Missing `state` parameter (CSRF on login)
- `redirect_uri` validation bypass (open redirect / token theft)
- PKCE enforcement check
- Implicit flow detection
- `.well-known/openid-configuration` discovery

### 5. `cloud.s3_audit`
S3 bucket misconfiguration scanner:
- Public bucket listing (ListBucket)
- Public object read (anonymous access)
- AllUsers READ ACL grants
- Auto-generates bucket name candidates from company names

---

## 🌐 Web Dashboard Upgrades

- **Real-time scan progress** via WebSocket (`/ws/scan`) — watch phases stream live
- **Token-based API auth** — set `NEXUS_DASHBOARD_TOKEN` to secure all `/api/*` endpoints
- **Dark/light theme toggle** — persists preference to localStorage
- **Mobile-responsive design** — collapsible sidebar, hamburger menu, stacked grids

---

## 🛠️ CLI Improvements

- **`nexus skills` command** — list, show, and run security skills from the terminal
- Version bumped to `1.0.0` everywhere

---

## 🐛 Bug Fixes

- **`web/server.py:73` get_stats crash** — findings are now normalized (str or dict) before severity counting
- **`webapi` domain missing `__init__.py`** — now a proper package
- **Version consistency** — `nexus/__init__.py`, `pyproject.toml`, and CLI all report `1.0.0`

---

## 📦 Distribution

- **PyPI-ready package** — `pip install nexus-strike` (build verified via `python -m build`)
- **GitHub Action** — `.github/action.yml` composite action for CI scans
- **Multi-stage Dockerfile** — minimal runtime with non-root user + HEALTHCHECK
- **Multi-service docker-compose** — nexus + ollama + redis + postgres
- **CI matrix** — GitHub Actions tests on Python 3.10, 3.11, and 3.12

---

## 👨‍💻 Who Is This For?

| Audience | Use case |
|---|---|
| **Penetration testers** | Authorized assessments with real, working tools |
| **SOC analysts** | Defensive scanning and threat intel |
| **Developers** | AppSec scanning in CI/CD pipelines |
| **Compliance teams** | Audit evidence and report generation |
| **Bug bounty hunters** | Target enumeration and vuln validation |
| **Students** | Learn offensive and defensive security |

---

## ⚡ Quick Start

```bash
# Install
pip install -e .

# Copy environment
cp .env.example .env

# Run a live scan against localhost
nexus live --target 127.0.0.1

# List all tools
nexus tools

# List all skills
nexus skills list

# Run a skill
nexus skills run web_security --target example.com

# Launch the web dashboard
nexus view
```

---

## 🛡️ Security Considerations

This is a **professional security tool**. You must have written authorization before scanning any system you do not own.

- **7 guardrails** enforce: input validation, scope, legal ack, escalation, rate limiting, audit logging, and output sanitization
- **Engagement records** (`nexus engage`) create signed audit trails
- **Authorization is required** — `NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION`
- **No black-hat tooling** — only white-hat & grey-hat detection/fingerprinting
- All findings use the standardized `Finding` schema

---

## 🗺️ Roadmap

- SOC integrations (Splunk, QRadar, Elastic, Sentinel)
- Compliance report generators (PCI/HIPAA/SOC2/NIST)
- Threat intel feeds (CVE stream, MISP, OTX, Shodan)
- SBOM generator with vuln correlation
- Scheduled scans and webhook notifications
- Multi-language support (Tamil, Hindi, Spanish, French)

---

## 🤝 Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [docs/extension_guide.md](extension_guide.md) for development guidelines.

---

## 📝 License

MIT — see [LICENSE](../LICENSE).

---

*Built by HARINISH — The Ultimate AI-Powered Cybersecurity Platform*