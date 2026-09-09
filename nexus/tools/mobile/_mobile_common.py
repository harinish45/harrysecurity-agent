#!/usr/bin/env python3
"""
NEXUS-STRIKE — mobile tools shared helpers (not a tool itself, not registered).

Mobile analysis is inherently FILE-based (.apk/.ipa archives) or
DEVICE-based (adb/libimobiledevice/frida) — there is no network-observable
substitute the way HTTP/TLS/DNS-based tools have one. Every mobile.* tool
in this package used to ignore its `target` entirely and instead resolve
DNS + issue a bare HTTP GET to `/`, unrelated to the tool's name, always
reporting status "completed" — caught during an audit alongside
hardware.usb_attacks. This module centralises the REAL, honest logic that
replaced those stubs:

  - parse_apk() / parse_ipa(): real zipfile-based archive parsing (APKs and
    IPAs are ZIP files). Uses `androguard` for authoritative AndroidManifest
    parsing when installed; otherwise falls back to documented best-effort
    heuristics (byte-level presence/string checks) rather than fabricating
    structured manifest data it can't actually extract.
  - frida_status() / adb_status() / idevice_status(): real prerequisite +
    liveness checks for the device-dependent tools (cert pinning bypass,
    dynamic instrumentation, root/jailbreak detection). No device access is
    ever fabricated — these either genuinely talk to a real, attached
    device/emulator or report why they could not.

Every mobile.* tool built on top of this module must honestly degrade
(STATUS_REQUIRES_HARDWARE / STATUS_OUT_OF_SCOPE / STATUS_FAILED, per
nexus/foundation/schema.py) when its real prerequisite isn't met, rather
than reporting STATUS_COMPLETED for something it didn't actually do.
"""
from __future__ import annotations

import importlib.util
import plistlib
import re
import shutil
import subprocess
import zipfile
from typing import Any


# ── APK (Android) ────────────────────────────────────────────────────────

def parse_apk(path: str) -> dict[str, Any]:
    """Real, zipfile-based parsing of an APK file (APKs are ZIP archives).

    Uses `androguard` for authoritative manifest parsing when the package is
    installed; otherwise falls back to documented best-effort presence/byte
    heuristics. Never fabricates data it can't actually extract.
    """
    result: dict[str, Any] = {
        "valid": False,
        "error": "",
        "entry_count": 0,
        "has_classes_dex": False,
        "has_manifest": False,
        "has_network_security_config": False,
        "native_libs": [],
        "androguard_used": False,
        "androguard_error": "",
        "permissions": [],
        "debuggable": None,
        "package_name": "",
        "min_sdk": "",
        "manifest_string_hits": [],
    }
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            manifest_bytes = z.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
    except (zipfile.BadZipFile, FileNotFoundError, OSError, KeyError) as e:
        result["error"] = f"Not a valid ZIP/APK archive: {e}"
        return result

    result["valid"] = True
    result["entry_count"] = len(names)
    result["has_classes_dex"] = any(n == "classes.dex" or re.match(r"classes\d*\.dex$", n) for n in names)
    result["has_manifest"] = "AndroidManifest.xml" in names
    result["has_network_security_config"] = any("network_security_config" in n.lower() for n in names)
    result["native_libs"] = sorted(n for n in names if n.startswith("lib/") and not n.endswith("/"))

    androguard_available = importlib.util.find_spec("androguard") is not None
    if androguard_available:
        try:
            from androguard.core.apk import APK  # type: ignore

            apk = APK(path)
            result["androguard_used"] = True
            result["package_name"] = apk.get_package() or ""
            result["permissions"] = list(apk.get_permissions() or [])
            result["debuggable"] = bool(apk.is_debuggable())
            result["min_sdk"] = apk.get_min_sdk_version() or ""
        except Exception as e:  # pragma: no cover - only exercised when androguard is installed
            result["androguard_error"] = str(e)

    if not result["androguard_used"] and manifest_bytes:
        # Best-effort heuristic only (no androguard available): the compiled
        # binary AXML format stores strings UTF-16LE-encoded in its string
        # pool, so a plain substring search finds them; a plaintext manifest
        # (e.g. a test fixture) is matched via the ASCII fallback. This is a
        # real, if imprecise, signal — not a fabricated structured parse.
        candidates = [
            "android:debuggable",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_CONTACTS",
        ]
        result["manifest_string_hits"] = scan_bytes_for_strings(manifest_bytes, candidates)
        if "android:debuggable" in result["manifest_string_hits"]:
            result["debuggable"] = True

    return result


def scan_bytes_for_strings(data: bytes, candidates: list[str]) -> list[str]:
    """Search raw bytes for each candidate string, trying both a plain ASCII
    match (plaintext / test fixtures) and a UTF-16LE match (how compiled
    Android binary XML stores its string pool). Real byte-level search —
    not a fabricated result."""
    found = []
    for c in candidates:
        if c.encode("utf-8") in data or c.encode("utf-16-le") in data:
            found.append(c)
    return found


# ── IPA (iOS) ─────────────────────────────────────────────────────────────

def parse_ipa(path: str) -> dict[str, Any]:
    """Real, zipfile-based parsing of an IPA file (IPAs are ZIP archives),
    using stdlib `plistlib` to parse the app bundle's Info.plist."""
    result: dict[str, Any] = {
        "valid": False,
        "error": "",
        "entry_count": 0,
        "info_plist_path": "",
        "info_plist": {},
        "ats_arbitrary_loads": False,
        "bundle_id": "",
        "bundle_name": "",
    }
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as e:
        result["error"] = f"Not a valid ZIP/IPA archive: {e}"
        return result

    result["valid"] = True
    result["entry_count"] = len(names)

    plist_candidates = [n for n in names if re.match(r"^Payload/[^/]+\.app/Info\.plist$", n)]
    if not plist_candidates:
        result["error"] = "No Payload/<AppName>.app/Info.plist found — not a standard IPA bundle structure"
        return result

    plist_path = plist_candidates[0]
    result["info_plist_path"] = plist_path
    try:
        with zipfile.ZipFile(path) as z:
            plist_bytes = z.read(plist_path)
        plist_data = plistlib.loads(plist_bytes)
        if isinstance(plist_data, dict):
            result["info_plist"] = plist_data
            result["bundle_id"] = plist_data.get("CFBundleIdentifier", "")
            result["bundle_name"] = plist_data.get("CFBundleName") or plist_data.get("CFBundleDisplayName", "")
            ats = plist_data.get("NSAppTransportSecurity")
            if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
                result["ats_arbitrary_loads"] = True
    except Exception as e:
        result["error"] = f"Failed to parse Info.plist: {e}"

    return result


# ── Device-dependent prerequisite checks ────────────────────────────────

def frida_status() -> dict[str, Any]:
    """Real check for frida availability + a genuinely attached USB device.
    Read-only: only lists what's already there, never injects anything."""
    status: dict[str, Any] = {
        "frida_python_installed": False,
        "frida_ps_installed": bool(shutil.which("frida-ps")),
        "device_attached": False,
        "device_id": "",
        "device_name": "",
        "frida_version": "",
        "error": "",
    }
    if importlib.util.find_spec("frida") is None:
        status["error"] = "frida Python package is not installed in this environment"
        return status
    try:
        import frida  # type: ignore

        status["frida_python_installed"] = True
        status["frida_version"] = getattr(frida, "__version__", "")
    except Exception as e:  # pragma: no cover
        status["error"] = f"frida import failed: {e}"
        return status
    try:
        device = frida.get_usb_device(timeout=1)
        status["device_attached"] = True
        status["device_id"] = getattr(device, "id", "")
        status["device_name"] = getattr(device, "name", "")
    except Exception as e:
        status["error"] = f"No USB device reachable via frida: {e}"
    return status


def adb_status() -> dict[str, Any]:
    """Real check for the `adb` binary + an actually-connected device
    (parses `adb devices` output for a live '<serial>\\tdevice' line)."""
    status: dict[str, Any] = {
        "adb_installed": bool(shutil.which("adb")),
        "device_connected": False,
        "devices": [],
        "raw_output": "",
        "error": "",
    }
    if not status["adb_installed"]:
        status["error"] = "adb binary not found on PATH (Android Platform Tools not installed)"
        return status
    try:
        proc = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=10
        )
        status["raw_output"] = proc.stdout.strip()
        lines = proc.stdout.splitlines()[1:] if proc.stdout else []
        devices = [ln.split("\t")[0] for ln in lines if ln.strip() and "\tdevice" in ln]
        status["devices"] = devices
        status["device_connected"] = len(devices) > 0
        if not devices:
            status["error"] = "adb is installed but no authorized device/emulator is currently connected"
    except Exception as e:
        status["error"] = f"adb devices failed: {e}"
    return status


def idevice_status() -> dict[str, Any]:
    """Real check for `idevice_id` (libimobiledevice) + an actually-connected
    iOS device."""
    status: dict[str, Any] = {
        "idevice_id_installed": bool(shutil.which("idevice_id")),
        "device_connected": False,
        "devices": [],
        "error": "",
    }
    if not status["idevice_id_installed"]:
        status["error"] = "idevice_id binary not found on PATH (libimobiledevice not installed)"
        return status
    try:
        proc = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=10)
        udids = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        status["devices"] = udids
        status["device_connected"] = len(udids) > 0
        if not udids:
            status["error"] = "idevice_id is installed but no paired iOS device is currently connected"
    except Exception as e:
        status["error"] = f"idevice_id -l failed: {e}"
    return status


def is_apk_target(target: str) -> bool:
    import os
    return isinstance(target, str) and target.lower().endswith(".apk") and os.path.isfile(target)


def is_ipa_target(target: str) -> bool:
    import os
    return isinstance(target, str) and target.lower().endswith(".ipa") and os.path.isfile(target)
