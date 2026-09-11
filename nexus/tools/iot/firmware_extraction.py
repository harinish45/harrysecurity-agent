#!/usr/bin/env python3
"""
NEXUS-STRIKE — iot tool: Firmware Extraction
Domain: iot

Previously byte-for-byte identical to smart_device_assessment.py (a plain
DNS-resolve + common-IoT-port scan) — despite the name, it did no
firmware-related work at all. Caught during this session's audit. Now:
real HTTP probing for exposed firmware-update endpoints, a common
misconfiguration on embedded/IoT web management interfaces.
"""
import socket
import urllib.error
import urllib.request

from nexus.foundation.net import safe_urlopen
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_USER_AGENT = "NEXUS-STRIKE/0.2.0 (FirmwareExtraction)"

# Common firmware-update/download paths seen on embedded device web UIs
# (routers, IP cameras, DVRs/NVRs, industrial controllers).
_FIRMWARE_PATHS = [
    "/firmware.bin", "/firmware/latest", "/firmware/upgrade",
    "/update.bin", "/fw.bin", "/upgrade.bin",
    "/cgi-bin/firmwareupload", "/cgi-bin/upgrade.cgi", "/upgrade.cgi",
    "/download/firmware", "/api/firmware", "/system/firmware",
]

_BINARY_CONTENT_TYPES = ("application/octet-stream", "application/x-binary", "application/firmware")


def _probe_path(target: str, path: str, timeout: int = 5) -> dict | None:
    url = f"http://{target}{path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="GET")
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        content_type = resp.headers.get("Content-Type", "").lower()
        content_length = resp.headers.get("Content-Length", "?")
        return {"path": path, "url": url, "status": resp.status,
                "content_type": content_type, "content_length": content_length}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return {"path": path, "url": url, "status": e.code, "content_type": "", "content_length": "?"}
    except Exception:
        return None


def run(target: str, **kwargs) -> dict:
    """iot tool: Firmware Extraction"""
    findings = []
    try:
        try:
            socket.gethostbyname(target)
        except socket.gaierror as e:
            findings.append(f"DNS resolution failed for {target}: {e}")
            return {"tool": "iot.firmware_extraction", "domain": "iot", "target": target,
                    "status": "completed", "findings": findings}

        discovered = []
        for path in _FIRMWARE_PATHS:
            result = _probe_path(target, path)
            if result is not None:
                discovered.append(result)

        if not discovered:
            findings.append(
                f"No common firmware-update endpoints found on {target} "
                f"(checked {len(_FIRMWARE_PATHS)} known paths)"
            )
        else:
            for item in discovered:
                is_binary = any(ct in item["content_type"] for ct in _BINARY_CONTENT_TYPES)
                if is_binary:
                    findings.append(
                        f"Possible exposed firmware download at {item['url']}: "
                        f"status={item['status']}, Content-Type={item['content_type']}, "
                        f"Content-Length={item['content_length']} — verify this doesn't allow "
                        f"unauthenticated firmware extraction"
                    )
                else:
                    findings.append(
                        f"Firmware-update-shaped endpoint reachable at {item['url']}: "
                        f"status={item['status']}, Content-Type={item['content_type'] or 'unknown'} "
                        f"— not confirmed binary, worth manual follow-up"
                    )
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "iot.firmware_extraction", "domain": "iot", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("iot.firmware_extraction", run, metadata={
    "name": "iot.firmware_extraction",
    "domain": "iot",
    "status": "completed",
    "description": "iot tool: probes for exposed firmware-update endpoints over HTTP (real check, not a port-scan duplicate)",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
