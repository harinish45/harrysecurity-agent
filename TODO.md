# ✅ Autonomous Implementation Checklist (Vibe Coding Guide)

This checklist is structured for AI coding agents (Antigravity, Cursor, Claude Code, Copilot). Pick the first unchecked item `[ ]`, implement, test, and mark as `[x]`.

---

## 🎯 Phase 5: "No Fake/Mock" Hardening Pass (real live-test findings + parallel-agent fixes)
- [x] `verification_agent`: timing-based false-positive detection — a real HIGH-severity finding from a live test (`"Delay: 8.1s via payload: ; sleep 3"`) was actually network jitter, not command execution. Added `_verify_timing()`: detects `webapp.cmdi`'s time-based-injection evidence format, measures a real baseline (4 samples, no payload) vs. a payload replay, and reports a new `likely_false_positive` status when the claimed delay collapses into baseline noise — never auto-escalates to `verified` from timing alone. Wired into `generator.py`/`html_export.py` for report display.
- [x] `nexus/tools/compliance/*.py` (9 files) — were byte-for-byte identical (generic DNS+4-header check under 9 framework names). Each now has real, framework-specific, network-observable logic: PCI DSS (TLS cipher/protocol strength + payment-form-over-HTTP), GDPR (pre-consent cookies + privacy-policy page), HIPAA (forced-HTTPS + HSTS max-age), ISO 27001 (headers mapped to named Annex A control IDs), NIST 800-53 (version-banner + robots.txt sensitive-path disclosure), NIST CSF (real SPF/DMARC DNS TXT lookups), policy reviews (RFC 9116 security.txt + robots.txt), risk assessments (severity-weighted upstream aggregation + live port probe), security audits (header hygiene + directory-listing detection). 18 tests in `tests/unit/test_compliance_tools.py`, plus live-network spot checks against example.com.
- [x] `active_directory.kerberoast` — previously fabricated SPN findings unconditionally (`f"MSSQLSvc/{target}:1433"`, string-templated, no LDAP query ever made). Now performs a real anonymous-bind LDAP search (`ldap3`, added to requirements.txt); honestly reports `requires_credentials`/`unavailable` instead of fabricating when no real SPN data can be obtained.
- [x] `hardware.usb_attacks` / `hardware.rfid_testing` — previously ignored `target` and reported the *local machine's* platform info as a completed target assessment. Now honestly report `STATUS_REQUIRES_HARDWARE` (a physical USB/RFID device against the real target is unavoidable) instead of fabricating coverage.
- [x] Playwright MCP server installed (`claude mcp add playwright`, Chromium downloaded) and verified connected via `claude mcp list` — its tools need a session restart to appear in an already-running session.

---

## 🎯 Phase 1: Benchmark Suite Hardening
- [x] `nexus/benchmarks/agent_eval.py`: Integrate automated evaluation harness
  - [x] Add precision/recall metrics for `debate_consensus_agent` — `evaluate_debate_consensus()` scores it against 6 hand-labeled real/false-positive cases (F1, disagreement counted as "abstained" not a wrong answer); `nexus benchmark --suite debate_consensus_eval`, history in `benchmarks/debate_eval_history.jsonl`
  - [x] Add execution latency benchmarks per agent — `benchmark_agent_latency()` times any agent set's real `.run()` call; `nexus benchmark --latency [--agent NAME ...]`, history in `benchmarks/latency_history.jsonl`
- [x] `tests/unit/test_v2_agents.py`: Unit tests for the newly integrated orchestrator agents
  - [x] Test `BudgetGuard` cap enforcement (raises `BudgetExceededError` over the configured token budget) — `budget_governor_agent` itself is a thin reporting wrapper around this, not a separate enforcement point
  - [x] Test `mitre_mapping_agent` ATT&CK technique tagging
  - [x] Test `evaluate_debate_consensus`/`benchmark_agent_latency` (perfect-agent scoring, disagreement-as-abstain, named-agent timing, unknown-agent handling)

## 🎯 Phase 2: Web Dashboard Live Streaming
- [x] `web/`: Wire real-time agent message stream
  - [x] `FlowController` emits `batch_start`/`agent_done` events; `nexus <mode> --target ...` (mission modes) prints them as tagged `NEXUS-EVENT:{json}` stdout lines when `NEXUS_EMIT_EVENTS=1`; `web/server.py`'s scan subprocess reader parses these into structured `agent_event` WebSocket messages instead of raw text — see `scan_start`'s `mode` payload field and `_stream_output`. Dashboard mode switcher + a per-agent "Live Agent Stream" panel are wired in `index.html`/`app.js`.
  - [x] Real-time MITRE matrix visual heat-map — `GET /api/mitre-coverage` aggregates `mitre_techniques` across the latest mission's findings; rendered as a severity-colored grid in the new "Mission Analysis" panel (MITRE Coverage tab)
  - [x] Stream `debate_consensus_agent`'s individual skeptic/analyst rounds — `on_round` callback fires after each pass and the final consensus; `OrchestrationEngine._debate_ambiguous` wires it to a `debate_round` event when `emit_events` is on; rendered per-finding in the Live Agent Stream panel
  - [x] `GET /api/benchmarks` — score-over-time data path (still no chart, only a table-ready JSON array; a chart is cheap to add on top whenever wanted)
  - [x] Attack Graph view — `GET /api/attack-graph` renders the same `AttackGraphViz` SVG the HTML report uses, embedded live in a dashboard tab
  - [x] Findings/Triage board (Kanban) — client-side grouping of `/api/findings` by `verification_status` (non_replayable / unverified / failed / verified / not-yet-verified) in a new Triage Board tab
  - [x] Report Viewer — `GET /api/report-tone?mode=X` renders `report_tone_agent` output for the latest mission per mode (pentest/bounty/ctf/redteam/blueteam/compliance) in a Report Preview tab with a mode selector
  - [x] Budget meter — `GET /api/budget` (BudgetGuard total + configured caps if any) polled every 5s into a live meter next to the scan controls

## 🎯 Phase 3: Automotive Security Laboratory Suite
- [x] `nexus/tools/automotive/`: Full-featured ECU, CAN bus, IVN & firmware security analyzer
  - [x] `can_bus_analysis.py`: Real arbitration ID decoding (11-bit/29-bit), OBD-II diagnostic PIDs (Speed, DTCs, Actuators), ISO 11898 bus-off priority inversion DoS detection, SocketCAN & serial adapter discovery
  - [x] `ecu_reverse_engineering.py`: Real UDS (ISO 14229) diagnostic protocol analyzer, SecurityAccess (0x27) seed entropy & zero-seed/static-seed detection, ReadMemoryByAddress (0x23), WriteMemoryByAddress (0x3D), sensitive DID inspection (0xF190 VIN, 0xF180 Bootloader)
  - [x] `automotive_firmware_analysis.py`: Motorola S-Record (S19/S28/S37) & Intel HEX parser, Infineon TriCore (TC2xx/TC3xx), NXP PowerPC (MPC5xxx), ARM Cortex-R MCU fingerprinting, unencrypted firmware detection, hardcoded seed-key routine references, and Secure Boot signature verification
  - [x] `vehicle_network_testing.py`: In-Vehicle Network (IVN) analyzer covering Diagnostics over IP (DoIP / ISO 13400-2) unauthenticated routing activation, SOME/IP Service Discovery (SOME/IP-SD) assessment, and gateway domain separation (Infotainment vs Powertrain/ADAS)
  - [x] `tests/unit/test_automotive_tools.py`: 9 comprehensive unit tests verifying all tools and `AutomotiveAgent` execution

## 🎯 Phase 4: Benchmark Dashboard, Datasets, Digital-Twin Hardening
- [x] Benchmark Dashboard page (`web/templates/index.html`, `web/static/js/app.js`) — new "Benchmarks" nav entry with a Chart.js score-over-time line chart (one line per suite: intercode_ctf/cybench/nyu_ctf/debate_consensus_eval), plus tables for the debate-eval precision/recall/F1 history and the latest agent-latency run. Backed by 2 new read-only endpoints in `web/server.py`: `GET /api/benchmarks/latency`, `GET /api/benchmarks/debate-eval` (same tolerant newest-first pattern as the existing `GET /api/benchmarks`).
- [x] `benchmarks/data/cybench/` (9 challenges) and `benchmarks/data/nyu_ctf/` (7 challenges), spanning pwn/crypto/web/rev/forensics/misc — original, self-written, single-answer, regex-checkable challenges in the spirit/difficulty tier of each named suite. **Not the official published Cybench/NYU-CTF-Bench datasets** (those are licensed academic benchmarks this repo has no rights to bundle) — see `benchmarks/data/README.md` for the disclaimer and how to swap in the real datasets (same JSON shape, no code changes needed) if you have access to them.
- [x] `digital_twin_agent.py` test coverage (`tests/unit/test_digital_twin_agent.py`, 8 tests, Docker fully mocked — no daemon needed) + one real bug fixed: `check_command` had no type validation before being passed to `subprocess.run(..., shell=False)`, which would fail cryptically if ever called with a string instead of a list (every other `subprocess.run()` call in this codebase uses a list). Now returns a clear `unavailable` result instead. One `TODO` left in place (not fixed): a `docker run` that times out client-side could theoretically leak a server-side container — no live Docker daemon in this environment to validate a fix against.

## 🎯 Phase 6: Running NEXUS-STRIKE for $0
- [x] `.env.example` LLM block rebuilt: every provider now has an inline 🟢/🟡/🔴 cost label verified against real 2026-09 pricing (not assumed), and previously entirely-missing OpenAI/Anthropic/Azure/DeepSeek key placeholders were added (a new user had no way to even discover these paid options existed before).
- [x] `nexus providers` (`cli.py`) gained a real "Cost" column (🟢 Free / 🟢 Free tier / 🟡 Very low cost / 🔴 Paid only / ❓ Depends) per provider, plus a runtime warning when the active provider has no free tier.
- [x] README.md: new "Running NEXUS-STRIKE for $0" section — verified-accurate free/paid table for all 10 LLM providers, a recommended zero-cost setup (Ollama primary, Groq fallback), and which recon tools already run fully free by default (`shodan_search` via free InternetDB, `cert_transparency` via crt.sh, `github_recon` via GitHub's public search API) vs. honestly degrade without a paid key (`censys_search`, some `ai_security` tools).
