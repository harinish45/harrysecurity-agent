# Agent Guide

## Overview

NEXUS-STRIKE uses a mesh of specialized AI agents that orchestrate security tools and interpret results. Agents are organized into tiers based on their role in the security assessment lifecycle.

## Agent Tiers

### Offensive Agents
| Agent | Description |
|-------|-------------|
| `recon_agent` | Host discovery, DNS resolution, subdomain enumeration, technology fingerprinting |
| `network_agent` | Port scanning, service detection, banner grabbing, firewall detection |
| `webapp_agent` | SQLi, XSS, LFI, CMDi, SSRF, directory enumeration testing |
| `exploit_agent` | Exploit development and vulnerability exploitation |
| `ad_agent` | Active Directory attack path enumeration (Kerberoast, AS-REP, ACL abuse) |
| `cloud_agent` | Cloud infrastructure assessment (AWS, Azure, GCP) |
| `mobile_agent` | Mobile application security testing (Android/iOS) |
| `wireless_agent` | Wireless network security assessment |
| `redteam_agent` | Full-scope red team operations emulation |
| `social_eng_agent` | Social engineering campaign simulation |
| `api_attacker_agent` | REST/GraphQL API security testing |

### Defensive Agents
| Agent | Description |
|-------|-------------|
| `soc_agent` | Security operations center monitoring and alert triage |
| `ir_agent` | Incident response coordination and execution |
| `threat_hunt_agent` | Proactive threat hunting across infrastructure |
| `detection_engineer_agent` | Detection rule development and tuning |
| `blue_team_agent` | Defensive security posture assessment |
| `hardening_agent` | System and network hardening recommendations |
| `deception_agent` | Honeypot and deception technology deployment |

### Analysis Agents
| Agent | Description |
|-------|-------------|
| `malware_agent` | Malware analysis (static, dynamic, behavioral) |
| `forensics_agent` | Digital forensics (disk, memory, network, registry) |
| `reverse_eng_agent` | Reverse engineering of binaries and protocols |
| `threat_intel_agent` | Threat intelligence gathering and correlation |
| `vuln_analyst_agent` | Vulnerability correlation, risk scoring, prioritization |
| `crypto_agent` | Cryptography analysis and PKI assessment |
| `code_review_agent` | Secure code review across languages |
| `osint_analyst_agent` | Open-source intelligence gathering |
| `supply_chain_agent` | Supply chain security assessment |

### Orchestrator Agents
| Agent | Description |
|-------|-------------|
| `mission_commander_agent` | High-level mission planning and strategy |
| `task_planner_agent` | Task decomposition and scheduling |
| `agent_router_agent` | Dynamic agent selection based on task requirements |
| `pattern_selector_agent` | Attack pattern selection and sequencing |
| `quality_assessor_agent` | Result quality validation and completeness checking |

### Specialized Agents
| Agent | Description |
|-------|-------------|
| `iot_agent` | IoT device security assessment |
| `ot_ics_agent` | OT/SCADA security assessment |
| `automotive_agent` | Automotive (CAN bus, ECU) security testing |
| `hardware_agent` | Hardware security testing (JTAG, side-channel, TPM) |
| `rf_sdr_agent` | RF and SDR security analysis |
| `ai_security_agent` | AI/ML security assessment (prompt injection, model extraction) |
| `compliance_auditor_agent` | Compliance auditing (PCI DSS, HIPAA, GDPR, SOC 2) |
| `embedded_agent` | Embedded system security assessment |

### Support Agents
| Agent | Description |
|-------|-------------|
| `searcher_agent` | Information retrieval and knowledge base search |
| `coder_agent` | Code generation and script automation |
| `installer_agent` | Tool installation and environment setup |
| `reporter_agent` | Report generation and findings documentation |
| `validator_agent` | Finding validation and false positive verification |
| `debugger_agent` | Debugging and troubleshooting automation |
| `doc_writer_agent` | Documentation generation |
| `hitl_liaison_agent` | Human-in-the-loop interaction management |

## Creating a Custom Agent

1. Create a new file in the appropriate tier directory under `nexus/agents/`
2. Extend `BaseAgent` from `nexus.agents.base_agent`
3. Implement the `async def run(self, task: str, **kwargs) -> dict` method
4. Register the agent in `nexus/agents/agent_registry.py`

```python
from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry

class MyCustomAgent(BaseAgent):
    name = "my_custom_agent"
    description = "Description of my agent"

    async def run(self, task: str, **kwargs) -> dict:
        target = kwargs.get("target", "")
        findings = []
        
        # Use tools from registry
        tool_fn = tool_registry.get("webapp.my_tool")
        result = tool_fn(target=target)
        if result.get("findings"):
            findings.extend(result["findings"])
        
        return {"agent": self.name, "task": task, "status": "completed", "findings": findings}