#!/usr/bin/env python3
"""
NEXUS-STRIKE — red_team.lateral_movement_simulation
Domain: red_team
Safe MITRE ATT&CK Lateral Movement (TA0008) simulation. Never authenticates
or moves anything — performs a real, safe TCP connect-probe of the ports
lateral-movement techniques actually use (RDP/SMB/SSH/WinRM) to establish
genuine target context (is the surface even reachable?), then reports the
detection-relevant SIGNAL a blue team should see for each technique if it
WERE executed — the same pattern as purple_team.threat_simulation.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry
from nexus.tools.red_team._ttp_common import resolve_target, tcp_probe, simulate_ttp_phase

_TOOL_NAME = "red_team.lateral_movement_simulation"
_TACTIC = "Lateral Movement"

# (technique_id, technique_name, detection_hint, relevant_port_or_None)
_TECHNIQUES: list[tuple[str, str, str, int | None]] = [
    ("T1021.001", "Remote Desktop Protocol",
     "RDP logon to internal host (Windows Event 4624 Type 10) plus new process from the RDP session", 3389),
    ("T1021.002", "SMB/Windows Admin Shares",
     "Lateral SMB connection with admin-share access (Event 5140 on ADMIN$/C$) followed by remote service creation (Event 7045)", 445),
    ("T1021.004", "SSH",
     "SSH session from an unusual internal source (auth.log 'Accepted password/publickey' from a peer host, not a jump box)", 22),
    ("T1021.006", "Windows Remote Management",
     "WinRM/PowerShell Remoting session establishment (Event 4624 Type 3 + WinRM Event 91/168 operational log)", 5985),
    ("T1550.002", "Pass the Hash",
     "NTLM authentication using a stolen hash (Event 4624 Type 3, LogonProcess=NtLmSsp, with no matching interactive logon)", None),
]


def run(target: str, simulate_detection: bool = True, seed: int | None = None, **kwargs: Any) -> dict:
    """Simulate MITRE ATT&CK Lateral Movement (TA0008) against a target.

    Parameters
    ----------
    target : str
        Target IP or hostname (the "next hop" in a lateral-movement chain).
    simulate_detection : bool
        Probabilistically simulate detection outcomes (70% detected).
    seed : int, optional
        Random seed for reproducible results.
    """
    ip, dns_note = resolve_target(target)
    if ip is None:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=dns_note)

    relevant_ports = sorted({p for *_ignore, p in _TECHNIQUES if p is not None})
    reachability = tcp_probe(ip, relevant_ports, timeout=1.5)

    techniques_for_sim = [(tid, name, hint) for tid, name, hint, _port in _TECHNIQUES]
    findings = simulate_ttp_phase(target, _TOOL_NAME, _TACTIC, techniques_for_sim, simulate_detection, seed)

    # Annotate each simulated finding's evidence with the real reachability
    # context for its port, where one exists — makes the simulation
    # target-informed instead of generic.
    port_by_tid = {tid: port for tid, _name, _hint, port in _TECHNIQUES}
    for f in findings:
        tid = f.title.split("(")[-1].rstrip(")")
        port = port_by_tid.get(tid)
        if port is not None:
            reachable = reachability.get(port, False)
            f.evidence += (
                f" Real port reachability check: TCP/{port} is "
                f"{'reachable' if reachable else 'not reachable'} from this vantage point "
                f"({'increases' if reachable else 'reduces'} real-world feasibility of this technique)."
            )

    reachable_ports = [p for p, ok in reachability.items() if ok]

    return tool_result(
        _TOOL_NAME, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=(
            f"Lateral Movement simulation complete: {len(techniques_for_sim)} technique(s) evaluated. "
            f"Real port reachability: {len(reachable_ports)}/{len(relevant_ports)} lateral-movement "
            f"port(s) reachable ({reachable_ports or 'none'})."
        ),
        metadata={
            "dns_resolved_ip": ip,
            "ports_checked": relevant_ports,
            "ports_reachable": reachable_ports,
            "tactics_simulated": [_TACTIC],
            "techniques_total": len(techniques_for_sim),
        },
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "red_team",
    "status": "completed",
    "description": (
        "MITRE ATT&CK Lateral Movement (TA0008) simulation — real, safe TCP reachability "
        "probe of RDP/SMB/SSH/WinRM ports (T1021.x) for target context, plus simulated "
        "detection-signal reporting for each technique (T1021.001/.002/.004/.006, T1550.002)."
    ),
    "parameters": {
        "target": "Target IP or hostname",
        "simulate_detection": "Model detection outcomes probabilistically (default: True)",
        "seed": "Random seed for reproducible results (optional)",
    },
})
