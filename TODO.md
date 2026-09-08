# ✅ Autonomous Implementation Checklist (Vibe Coding Guide)

This checklist is structured for AI coding agents (Antigravity, Cursor, Claude Code, Copilot). Pick the first unchecked item `[ ]`, implement, test, and mark as `[x]`.

---

## 🎯 Phase 1: Benchmark Suite Hardening
- [ ] `nexus/benchmarks/`: Integrate automated evaluation harness
  - [ ] Add precision/recall metrics for `debate_consensus_agent`
  - [ ] Add execution latency benchmarks per agent
- [ ] `tests/test_new_orchestrator_agents.py`: Unit tests for newly integrated orchestrators
  - [ ] Test `budget_governor_agent` cap enforcement
  - [ ] Test `mitre_mapping_agent` ATT&CK technique tagging

## 🎯 Phase 2: Web Dashboard Live Streaming
- [ ] `web/`: Wire real-time agent message stream
  - [ ] WebSocket streaming of agent debate rounds to frontend
  - [ ] Real-time MITRE matrix visual heat-map update
