from importlib import import_module

AGENT_REGISTRY = {
    "malware_agent": "nexus.agents.analysis.malware_agent.MalwareAgent",
    "forensics_agent": "nexus.agents.analysis.forensics_agent.ForensicsAgent",
    "reverse_eng_agent": "nexus.agents.analysis.reverse_eng_agent.ReverseEngAgent",
    "threat_intel_agent": "nexus.agents.analysis.threat_intel_agent.ThreatIntelAgent",
    "crypto_agent": "nexus.agents.analysis.crypto_agent.CryptoAgent",
    "code_review_agent": "nexus.agents.analysis.code_review_agent.CodeReviewAgent",
    "osint_analyst_agent": "nexus.agents.analysis.osint_analyst_agent.OsintAnalystAgent",
    "vuln_analyst_agent": "nexus.agents.analysis.vuln_analyst_agent.VulnAnalystAgent",
    "supply_chain_agent": "nexus.agents.analysis.supply_chain_agent.SupplyChainAgent",
    "soc_agent": "nexus.agents.defensive.soc_agent.SocAgent",
    "ir_agent": "nexus.agents.defensive.ir_agent.IrAgent",
    "threat_hunt_agent": "nexus.agents.defensive.threat_hunt_agent.ThreatHuntAgent",
    "detection_engineer_agent": "nexus.agents.defensive.detection_engineer_agent.DetectionEngineerAgent",
    "blue_team_agent": "nexus.agents.defensive.blue_team_agent.BlueTeamAgent",
    "hardening_agent": "nexus.agents.defensive.hardening_agent.HardeningAgent",
    "deception_agent": "nexus.agents.defensive.deception_agent.DeceptionAgent",
    "recon_agent": "nexus.agents.offensive.recon_agent.ReconAgent",
    "network_agent": "nexus.agents.offensive.network_agent.NetworkAgent",
    "webapp_agent": "nexus.agents.offensive.webapp_agent.WebappAgent",
    "exploit_agent": "nexus.agents.offensive.exploit_agent.ExploitAgent",
    "ad_agent": "nexus.agents.offensive.ad_agent.AdAgent",
    "cloud_agent": "nexus.agents.offensive.cloud_agent.CloudAgent",
    "mobile_agent": "nexus.agents.offensive.mobile_agent.MobileAgent",
    "wireless_agent": "nexus.agents.offensive.wireless_agent.WirelessAgent",
    "redteam_agent": "nexus.agents.offensive.redteam_agent.RedteamAgent",
    "social_eng_agent": "nexus.agents.offensive.social_eng_agent.SocialEngAgent",
    "physical_pen_agent": "nexus.agents.offensive.physical_pen_agent.PhysicalPenAgent",
    "api_attacker_agent": "nexus.agents.offensive.api_attacker_agent.ApiAttackerAgent",
    "phishing_agent": "nexus.agents.offensive.phishing_agent.PhishingAgent",
    "mission_commander_agent": "nexus.agents.orchestrator.mission_commander_agent.MissionCommanderAgent",
    "task_planner_agent": "nexus.agents.orchestrator.task_planner_agent.TaskPlannerAgent",
    "agent_router_agent": "nexus.agents.orchestrator.agent_router_agent.AgentRouterAgent",
    "pattern_selector_agent": "nexus.agents.orchestrator.pattern_selector_agent.PatternSelectorAgent",
    "quality_assessor_agent": "nexus.agents.orchestrator.quality_assessor_agent.QualityAssessorAgent",
    "iot_agent": "nexus.agents.specialized.iot_agent.IotAgent",
    "ot_ics_agent": "nexus.agents.specialized.ot_ics_agent.OtIcsAgent",
    "automotive_agent": "nexus.agents.specialized.automotive_agent.AutomotiveAgent",
    "hardware_agent": "nexus.agents.specialized.hardware_agent.HardwareAgent",
    "rf_sdr_agent": "nexus.agents.specialized.rf_sdr_agent.RfSdrAgent",
    "ai_security_agent": "nexus.agents.specialized.ai_security_agent.AiSecurityAgent",
    "compliance_auditor_agent": "nexus.agents.specialized.compliance_auditor_agent.ComplianceAuditorAgent",
    "embedded_agent": "nexus.agents.specialized.embedded_agent.EmbeddedAgent",
    "searcher_agent": "nexus.agents.support.searcher_agent.SearcherAgent",
    "coder_agent": "nexus.agents.support.coder_agent.CoderAgent",
    "installer_agent": "nexus.agents.support.installer_agent.InstallerAgent",
    "reporter_agent": "nexus.agents.support.reporter_agent.ReporterAgent",
    "validator_agent": "nexus.agents.support.validator_agent.ValidatorAgent",
    "debugger_agent": "nexus.agents.support.debugger_agent.DebuggerAgent",
    "doc_writer_agent": "nexus.agents.support.doc_writer_agent.DocWriterAgent",
    "hitl_liaison_agent": "nexus.agents.support.hitl_liaison_agent.HitlLiaisonAgent"
}

def list_agents():
    """
    Return an iterable of (agent_name, agent_class) tuples.
    Tests expect exactly two values per param.
    """
    agents = []
    for name in sorted(AGENT_REGISTRY):
        try:
            agents.append((name, get_agent(name)))
        except Exception:
            # Fallback to None if agent class cannot be loaded during test collection
            agents.append((name, None))
    return agents

def get_agent(name: str):
    path = AGENT_REGISTRY[name]
    mod_path, cls_name = path.rsplit('.', 1)
    return getattr(import_module(mod_path), cls_name)

def get_agent_count():
    return len(AGENT_REGISTRY)