"""
Auto-register all built-in skills into the class-based skill registry.
"""
from .skill_registry import skill_registry
from .web_security import WebSecuritySkill
from .code_security import CodeSecuritySkill
from .cloud_security import CloudSecuritySkill
from .reconnaissance import ReconnaissanceSkill
from .network_security import NetworkSecuritySkill
from .threat_intel import ThreatIntelSkill
from .compliance import ComplianceSkill

skill_registry.register("web_security", WebSecuritySkill)
skill_registry.register("code_security", CodeSecuritySkill)
skill_registry.register("cloud_security", CloudSecuritySkill)
skill_registry.register("reconnaissance", ReconnaissanceSkill)
skill_registry.register("network_security", NetworkSecuritySkill)
skill_registry.register("threat_intel", ThreatIntelSkill)
skill_registry.register("compliance", ComplianceSkill)
