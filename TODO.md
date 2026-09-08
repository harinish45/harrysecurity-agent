# ✅ Autonomous Implementation Checklist (Vibe Coding Guide)

This checklist is structured for AI coding agents (Antigravity, Cursor, Claude Code, Copilot). Pick the first unchecked item `[ ]`, implement, test, and mark as `[x]`.

---

## 🎯 Phase 1: Benchmark Suite Hardening
- [ ] `nexus/benchmarks/`: Integrate automated evaluation harness
  - [ ] Add precision/recall metrics for `debate_consensus_agent`
  - [ ] Add execution latency benchmarks per agent
- [x] `tests/unit/test_v2_agents.py`: Unit tests for the newly integrated orchestrator agents
  - [x] Test `BudgetGuard` cap enforcement (raises `BudgetExceededError` over the configured token budget) — `budget_governor_agent` itself is a thin reporting wrapper around this, not a separate enforcement point
  - [x] Test `mitre_mapping_agent` ATT&CK technique tagging

## 🎯 Phase 2: Web Dashboard Live Streaming
- [x] `web/`: Wire real-time agent message stream
  - [x] `FlowController` emits `batch_start`/`agent_done` events; `nexus <mode> --target ...` (mission modes) prints them as tagged `NEXUS-EVENT:{json}` stdout lines when `NEXUS_EMIT_EVENTS=1`; `web/server.py`'s scan subprocess reader parses these into structured `agent_event` WebSocket messages instead of raw text — see `scan_start`'s `mode` payload field and `_stream_output`. Dashboard mode switcher + a per-agent "Live Agent Stream" panel are wired in `index.html`/`app.js`.
  - [ ] Real-time MITRE matrix visual heat-map update (data is available per-finding via `mitre_mapping_agent`'s `technique_coverage`; no chart wired yet — html_export.py's Markdown/HTML reports render it as a coverage list today, not a live heat-map)
  - [ ] Stream `debate_consensus_agent`'s individual skeptic/analyst rounds (currently only the resolved/escalated summary reaches the report; the per-round exchange isn't itself streamed)
  - [ ] `GET /api/benchmarks` (added, reads `benchmarks/history.jsonl`) has no chart yet — data path only

## 🎯 Phase 3: Automotive Security Laboratory Suite
- [x] `nexus/tools/automotive/`: Full-featured ECU, CAN bus, IVN & firmware security analyzer
  - [x] `can_bus_analysis.py`: Real arbitration ID decoding (11-bit/29-bit), OBD-II diagnostic PIDs (Speed, DTCs, Actuators), ISO 11898 bus-off priority inversion DoS detection, SocketCAN & serial adapter discovery
  - [x] `ecu_reverse_engineering.py`: Real UDS (ISO 14229) diagnostic protocol analyzer, SecurityAccess (0x27) seed entropy & zero-seed/static-seed detection, ReadMemoryByAddress (0x23), WriteMemoryByAddress (0x3D), sensitive DID inspection (0xF190 VIN, 0xF180 Bootloader)
  - [x] `automotive_firmware_analysis.py`: Motorola S-Record (S19/S28/S37) & Intel HEX parser, Infineon TriCore (TC2xx/TC3xx), NXP PowerPC (MPC5xxx), ARM Cortex-R MCU fingerprinting, unencrypted firmware detection, hardcoded seed-key routine references, and Secure Boot signature verification
  - [x] `vehicle_network_testing.py`: In-Vehicle Network (IVN) analyzer covering Diagnostics over IP (DoIP / ISO 13400-2) unauthenticated routing activation, SOME/IP Service Discovery (SOME/IP-SD) assessment, and gateway domain separation (Infotainment vs Powertrain/ADAS)
  - [x] `tests/unit/test_automotive_tools.py`: 9 comprehensive unit tests verifying all tools and `AutomotiveAgent` execution

