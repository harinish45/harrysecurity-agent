"""Tags findings with MITRE ATT&CK technique IDs.

A small built-in keyword-to-technique table, not a full ATT&CK STIX import
— good enough to make every finding carry a technique tag, which is what
lets redteam mode (TTP-chain framing) and compliance mode (control mapping)
read off the *same* underlying finding data model instead of needing their
own separate tagging passes.
"""
from __future__ import annotations

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result

# (keyword, technique_id, technique_name) — first match wins, ordered
# roughly most-specific-first.
_TECHNIQUE_TABLE = (
    ("sql injection", "T1190", "Exploit Public-Facing Application"),
    ("sqli", "T1190", "Exploit Public-Facing Application"),
    ("xss", "T1189", "Drive-by Compromise"),
    ("cross-site scripting", "T1189", "Drive-by Compromise"),
    ("ssrf", "T1190", "Exploit Public-Facing Application"),
    ("command injection", "T1059", "Command and Scripting Interpreter"),
    ("cmdi", "T1059", "Command and Scripting Interpreter"),
    ("lfi", "T1083", "File and Directory Discovery"),
    ("path traversal", "T1083", "File and Directory Discovery"),
    ("phishing", "T1566", "Phishing"),
    ("credential", "T1552", "Unsecured Credentials"),
    ("password", "T1110", "Brute Force"),
    ("brute force", "T1110", "Brute Force"),
    ("token", "T1528", "Steal Application Access Token"),
    ("session", "T1539", "Steal Web Session Cookie"),
    ("privilege escalation", "T1068", "Exploitation for Privilege Escalation"),
    ("misconfiguration", "T1210", "Exploitation of Remote Services"),
    ("open port", "T1046", "Network Service Discovery"),
    ("port scan", "T1046", "Network Service Discovery"),
    ("subdomain", "T1590", "Gather Victim Network Information"),
    ("dns", "T1590", "Gather Victim Network Information"),
    ("tls", "T1557", "Adversary-in-the-Middle"),
    ("ssl", "T1557", "Adversary-in-the-Middle"),
    ("malware", "T1204", "User Execution"),
    ("persistence", "T1053", "Scheduled Task/Job"),
    ("lateral movement", "T1021", "Remote Services"),
    ("exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ("supply chain", "T1195", "Supply Chain Compromise"),
    ("cloud", "T1526", "Cloud Service Discovery"),
    ("active directory", "T1069", "Permission Groups Discovery"),
    ("wireless", "T1557", "Adversary-in-the-Middle"),
    ("iot", "T1200", "Hardware Additions"),
    ("prompt injection", "T1656", "Impersonation"),
)


class MitreMappingAgent(BaseAgent):
    name = "mitre_mapping_agent"
    description = "orchestrator agent that tags findings with MITRE ATT&CK technique IDs"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        findings = kwargs.get("findings", []) or []
        if not findings:
            return tool_result(self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                                summary="No findings to map to ATT&CK")

        annotated = []
        coverage: dict[str, int] = {}
        for f in findings:
            f = dict(f)
            techniques = self._techniques_for(f)
            f["mitre_techniques"] = techniques
            for t in techniques:
                coverage[t["id"]] = coverage.get(t["id"], 0) + 1
            annotated.append(f)

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"MITRE ATT&CK mapping applied to {len(annotated)} finding(s), "
                    f"{len(coverage)} distinct technique(s) covered",
            metadata={"annotated_findings": annotated, "technique_coverage": coverage},
        )

    def _techniques_for(self, finding: dict) -> list[dict]:
        haystack = f"{finding.get('title', '')} {finding.get('tool', '')}".lower()
        for keyword, tid, tname in _TECHNIQUE_TABLE:
            if keyword in haystack:
                return [{"id": tid, "name": tname, "url": f"https://attack.mitre.org/techniques/{tid}/"}]
        return []
