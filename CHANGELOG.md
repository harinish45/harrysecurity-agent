# Changelog

All notable changes to NEXUS-STRIKE are documented in this file.

## [1.0.0] - 2026-08-12

### Added
- **5 new real security tools**:
  - `reconnaissance.subdomain_takeover` — DNS CNAME + service signature takeover detection (AWS S3, CloudFront, GitHub Pages, Heroku, Azure, Pantheon, Tumblr, Shopify, Fastly, Bitbucket, Surge, Netlify, ReadTheDocs, Zendesk, Ghost)
  - `webapp.jwt_attacks` — JWT vulnerability suite: alg=none bypass, RS256→HS256 confusion, kid header injection, weak HMAC secret brute force, privilege escalation
  - `webapi.graphql_attacks` — GraphQL introspection, query depth abuse, and batching DoS detection
  - `webapi.oauth_audit` — OAuth/OIDC misconfiguration scanner: state param, redirect URI validation, PKCE enforcement, implicit flow
  - `cloud.s3_audit` — S3 bucket misconfiguration scanner: public listing, public read, weak ACLs
- **`nexus skills` CLI command** — list, show, and run security skills from the terminal
- **WebSocket real-time scan progress** (`/ws/scan`) — live phase/output streaming to the dashboard
- **Token-based dashboard auth** — set `NEXUS_DASHBOARD_TOKEN` to require `Authorization: Bearer <token>` on all `/api/*` endpoints
- **Dark/light theme toggle** — persisted to localStorage, default dark
- **Mobile-responsive dashboard** — collapsible sidebar with hamburger menu, stacked grids, horizontal-scroll tables
- **GitHub Action wrapper** (`.github/action.yml`) — run NEXUS-STRIKE scans in CI
- **Multi-stage Dockerfile** — builder + runtime stages, non-root user, HEALTHCHECK, OCI labels
- **Multi-service docker-compose** — nexus, ollama, redis, postgres with named volumes
- **PyPI-ready pyproject.toml** — classifiers, project URLs, entry points, dev extras

### Fixed
- **`web/server.py:73` get_stats crash** — findings are now normalized (str or dict) before severity counting
- **`webapi` domain missing `__init__.py`** — now a proper package with registered tools
- **Version consistency** — `nexus/__init__.py` bumped to 1.0.0

### Changed
- `pyproject.toml` version → 1.0.0
- `nexus/__init__.py` version → 1.0.0
- Dashboard now streams scan output via WebSocket instead of silent background process

### Security
- All new tools follow the `Finding` schema and `tool_result()` contract
- No black-hat tooling added — only white-hat and grey-hat detection/fingerprinting
- Dashboard token auth is opt-in via `NEXUS_DASHBOARD_TOKEN` (default: localhost dev mode)

## [0.2.0] - 2026-08-11

### Added
- Strix web dashboard (13-page SPA)
- Skills plugin system (7 domain skills)
- Agent/tool organization
- 4 new API endpoints

## [0.1.0] - 2026-08-10

### Added
- Initial release
- 266 tool files across 29 security domains
- 50 agents across 6 tiers
- 7 guardrails
- 10 LLM provider adapters
- Live agent with real port scanning, SQLi, XSS, LFI, CMDi, SSRF detection
- Report generation with CVE enrichment
- Engagement record system