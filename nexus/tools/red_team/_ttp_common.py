#!/usr/bin/env python3
"""
NEXUS-STRIKE — red_team shared TTP-simulation helpers.

Not a registered tool itself. Provides the small pieces every
red_team.*_simulation module needs so each module's file stays focused on
what makes IT specific (its own MITRE technique table and, where safe, its
own real target-informed check) rather than re-implementing plumbing:

- resolve_target()/tcp_probe(): tiny, safe, real network primitives (DNS
  resolution, a bare TCP connect) used to give a simulation genuine
  target context instead of operating in a vacuum.
- simulate_ttp_phase(): the same "simulate detection outcome per ATT&CK
  technique, emit a DETECTED/MISSED Finding either way" logic already
  established by purple_team.threat_simulation._run_simulation_phase —
  reused here (not duplicated) so every *_simulation tool reports findings
  in the same shape, with the same honesty about what is/isn't real.
"""
from __future__ import annotations

import random
import socket
from typing import Any

from nexus.foundation.schema import Finding


def resolve_target(target: str) -> tuple[str | None, str]:
    """Best-effort real DNS resolution of a target string.

    Returns (ip_or_None, human_readable_note). Never raises.
    """
    host = target.strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/", 1)[0].split(":", 1)[0]
    if not host:
        return None, "Empty target — nothing to resolve"
    try:
        ip = socket.gethostbyname(host)
        return ip, f"{host} resolves to {ip}"
    except OSError as exc:
        return None, f"DNS resolution failed for {host}: {exc}"


def tcp_probe(host: str, ports: list[int], timeout: float = 1.5) -> dict[int, bool]:
    """Real, safe TCP connect-probe (no payload sent) against a short port list.

    A bare connect+close — this is host/port liveness, not exploitation.
    Used by simulations that want to know whether the *surface* a technique
    would use is even reachable from here, without touching anything on it.
    """
    clean_host = host.strip()
    for prefix in ("https://", "http://"):
        if clean_host.lower().startswith(prefix):
            clean_host = clean_host[len(prefix):]
    clean_host = clean_host.split("/", 1)[0].split(":", 1)[0]

    results: dict[int, bool] = {}
    for port in ports:
        try:
            with socket.create_connection((clean_host, port), timeout=timeout):
                results[port] = True
        except OSError:
            results[port] = False
    return results


def simulate_ttp_phase(
    target: str,
    tool_name: str,
    tactic: str,
    techniques: list[tuple[str, str, str]],
    simulate_detection: bool = True,
    seed: int | None = None,
) -> list[Finding]:
    """Simulate one ATT&CK tactic's techniques and report DETECTED/MISSED findings.

    This is the exact pattern established by
    purple_team.threat_simulation._run_simulation_phase: it never executes the
    technique, it reports the detection-relevant SIGNAL a blue team should
    see if the technique WERE executed, so operators can validate whether
    that signal is actually wired up to an alert — Atomic-Red-Team-style safe
    emulation, not a real attack.

    Parameters
    ----------
    target : str
        Engagement/environment identifier or observed target.
    tool_name : str
        Fully-qualified tool name to stamp onto each Finding (e.g.
        ``red_team.lateral_movement_simulation``).
    tactic : str
        Human-readable ATT&CK tactic name for this phase.
    techniques : list[tuple[str, str, str]]
        ``(technique_id, technique_name, detection_hint)`` entries.
    simulate_detection : bool
        If True, probabilistically simulate a detection outcome per
        technique (70% detected) to model realistic coverage gaps.
    seed : int, optional
        Random seed for reproducible simulation results.
    """
    if seed is not None:
        random.seed(seed)

    findings: list[Finding] = []
    for technique_id, technique_name, detection_hint in techniques:
        detected = simulate_detection and random.random() < 0.70

        if detected:
            findings.append(Finding(
                title=f"[DETECTED] {tactic}: {technique_name} ({technique_id})",
                severity="info",
                confidence="certain",
                affected_asset=target,
                evidence=(
                    f"Simulation of {technique_id} ({technique_name}) was detected. "
                    f"Detection signal: {detection_hint}"
                ),
                remediation=(
                    "Control validated. Document the detection rule ID and alert fidelity. "
                    "Consider tuning to reduce false-negative rate."
                ),
                tool=tool_name,
                references=[f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"],
            ))
        else:
            findings.append(Finding(
                title=f"[MISSED] {tactic}: {technique_name} ({technique_id})",
                severity="high",
                confidence="high",
                affected_asset=target,
                evidence=(
                    f"Simulation of {technique_id} ({technique_name}) was NOT detected. "
                    f"Expected detection signal: {detection_hint}"
                ),
                remediation=(
                    f"Create or tune detection rule for {technique_id}. "
                    f"Expected log source: {detection_hint}. "
                    "Reference MITRE ATT&CK defensive techniques for guidance."
                ),
                tool=tool_name,
                references=[
                    f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    "NIST-SP-800-53-SI-4",
                ],
            ))

    return findings


__all__ = ["resolve_target", "tcp_probe", "simulate_ttp_phase"]
