# Roadmap

## Phase 1: Foundation

- [x] CLI with `nexus run` / `nexus live` commands
- [x] 266 tool files across 29 security domains
- [x] 56 agents across 6 tiers
- [x] 7 guardrails (Scope, Legal, Rate, Input, Escalation, Output, Audit)
- [x] 10 LLM provider adapters
- [x] Live agent with real port scanning, SQLi, XSS, LFI, CMDi, SSRF detection
- [x] Report generation with CVE enrichment
- [x] Engagement record system for authorized testing
- [x] Cross-phase authorization, tenant, evidence and mission contracts

## Phase 2: Production Hardening (In Progress)

- [x] CI/CD pipeline with automated testing
- [x] Docker image optimization (multi-stage, smaller footprint)
- [x] Kubernetes Helm chart
- [x] Dependency and static-security validation pipeline
- [x] Immutable tool sandbox policy for container runtimes
- [x] Result caching and deterministic deduplication primitives
- [x] Regression tests for cache and sandbox primitives
- [ ] Comprehensive e2e test suite against isolated fixtures
- [ ] Performance benchmarking and optimization
- [ ] Concrete Docker-per-tool execution adapter

## Phase 3: Advanced Features

- [ ] MCP server for IDE integration (Claude Desktop, Cursor)
- [ ] Web UI dashboard with real-time scan progress
- [ ] Multi-target orchestration and parallel missions
- [ ] Automated false positive reduction
- [ ] Custom playbook authoring and sharing
- [ ] Integration with vulnerability management platforms
- [ ] Scheduled recurring assessments

## Phase 4: Enterprise

- [x] RBAC primitives
- [x] Multi-tenant context primitives
- [ ] Multi-tenant SaaS deployment
- [ ] API-first architecture for third-party integrations
- [ ] Compliance reporting templates (PCI DSS, HIPAA, SOC 2)
- [ ] Advanced persistence with mission state storage
- [ ] Team collaboration features
- [ ] Audit trail for compliance evidence

## Phase 5: AI-Native

- [ ] Autonomous penetration testing with AI-driven decision making
- [ ] Natural language mission briefing and debriefing
- [ ] AI-generated exploit PoC generation
- [ ] Adaptive attack path generation
- [ ] ML-based anomaly detection in scan results
- [ ] Automated remediation playbook generation
