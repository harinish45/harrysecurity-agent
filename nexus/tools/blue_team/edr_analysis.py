#!/usr/bin/env python3
"""
NEXUS-STRIKE — blue_team tool: Edr Analysis
Domain: blue_team

Whether `target` itself is running an EDR/AV agent cannot be determined by
probing it over the network — that's exactly the kind of thing a real EDR
agent is designed to be invisible to unauthenticated network traffic, and
answering it for real requires either the EDR vendor's console API or a
credentialed/remote session on `target` itself. This previously did a DNS
resolve on `target` and checked a handful of HTTP security response
headers, calling that "EDR analysis" — unrelated to any endpoint agent —
caught during this session's audit.

Now: this honestly reports STATUS_REQUIRES_CREDENTIALS for `target` (no
network-observable substitute exists), but — as a genuine diagnostic
capability, following the same "note" pattern `hardware.usb_attacks` uses
— it enumerates the running-process list on the LOCAL analysis host (via
`psutil` when installed, else a platform-native `tasklist`/`ps` fallback)
and checks it against known EDR/AV process signatures. That result is
explicitly labeled as describing the analysis host, never `target`, to
avoid the mislabeling bug `hardware.usb_attacks` originally had.
"""
import platform
import subprocess

from nexus.foundation.schema import STATUS_REQUIRES_CREDENTIALS, tool_result
from nexus.tools.registry import tool_registry

_KNOWN_EDR_AV_PROCESSES = {
    "msmpeng.exe": "Microsoft Defender",
    "nissrv.exe": "Microsoft Defender (Network Inspection)",
    "mpdefendercoreservice.exe": "Microsoft Defender (Core Service)",
    "csfalconservice.exe": "CrowdStrike Falcon",
    "csfalconcontainer.exe": "CrowdStrike Falcon",
    "sentinelagent.exe": "SentinelOne",
    "sentinelservicehost.exe": "SentinelOne",
    "sentinelstaticengine.exe": "SentinelOne",
    "cb.exe": "Carbon Black",
    "repmgr.exe": "Carbon Black Rep Mgr",
    "repux.exe": "Carbon Black",
    "mcshield.exe": "McAfee / Trellix",
    "masvc.exe": "McAfee / Trellix Agent",
    "ekrn.exe": "ESET",
    "savservice.exe": "Sophos",
    "savadminservice.exe": "Sophos",
    "ccsvchst.exe": "Symantec / Norton",
    "smcgui.exe": "Symantec Endpoint Protection",
    "wrsa.exe": "Webroot",
    "xagt.exe": "FireEye / Trellix Agent",
    "tmccsf.exe": "Trend Micro",
    "tmlisten.exe": "Trend Micro",
    "clamd": "ClamAV",
    "freshclam": "ClamAV (updater)",
    "falcon-sensor": "CrowdStrike Falcon (Linux)",
    "sentinelone": "SentinelOne (Linux)",
    "auditd": "Linux audit daemon (EDR-adjacent telemetry)",
}


def _list_processes_psutil() -> list:
    import psutil  # local import: optional dependency
    return [p.info.get("name") for p in psutil.process_iter(["name"]) if p.info.get("name")]


def _list_processes_windows_fallback() -> list:
    proc = subprocess.run(
        ["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15,
    )
    names = []
    for line in proc.stdout.splitlines():
        first_field = line.split('","')[0].strip('"')
        if first_field:
            names.append(first_field)
    return names


def _list_processes_unix_fallback() -> list:
    proc = subprocess.run(["ps", "-eo", "comm="], capture_output=True, text=True, timeout=15)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _enumerate_local_processes():
    try:
        return _list_processes_psutil(), "psutil"
    except ImportError:
        pass
    try:
        if platform.system() == "Windows":
            return _list_processes_windows_fallback(), "tasklist"
        return _list_processes_unix_fallback(), "ps"
    except (OSError, subprocess.SubprocessError):
        return [], "unavailable"


def run(target: str, **kwargs) -> dict:
    """blue_team tool: Edr Analysis"""
    local_node = platform.node()
    local_platform = platform.platform()
    processes, method = _enumerate_local_processes()

    lower_map = {p.lower(): p for p in processes}
    found_locally = [
        {"process": lower_map[name], "vendor": vendor}
        for name, vendor in _KNOWN_EDR_AV_PROCESSES.items() if name in lower_map
    ]

    return tool_result(
        "blue_team.edr_analysis", target,
        status=STATUS_REQUIRES_CREDENTIALS,
        summary=f"Determining whether {target} itself runs an EDR/AV agent requires the EDR "
                f"vendor's console API or a credentialed/remote session on {target} — this "
                f"cannot be inferred from unauthenticated network traffic",
        error=f"requires_credentials: no EDR console API or remote-session access to {target}",
        metadata={
            "note": f"The process data below describes the machine nexus-strike itself is "
                    f"running on ({local_node}), NOT {target} — it is diagnostic context "
                    f"only, not a target assessment.",
            "local_node": local_node,
            "local_platform": local_platform,
            "detection_method": method,
            "local_processes_scanned": len(processes),
            "known_edr_av_agents_found_on_LOCAL_host": found_locally,
        },
    )


# Register with tool registry
tool_registry.register("blue_team.edr_analysis", run, metadata={
    "name": "blue_team.edr_analysis",
    "domain": "blue_team",
    "status": "requires_credentials",
    "description": "blue_team tool: honestly reports that target-side EDR/AV presence "
                    "requires credentialed access to the target; diagnostically enumerates "
                    "the LOCAL analysis host's own processes for known EDR/AV signatures",
    "parameters": {
        "target": "Target domain, IP, or URL (not queried directly — see description)",
    },
})
