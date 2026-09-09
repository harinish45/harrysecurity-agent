"""All 9 nexus/tools/mobile/ tools (android_analysis, apk_decompilation,
cert_pinning_bypass, dynamic_instrumentation, ios_analysis, ipa_analysis,
mobile_api_testing, mobile_malware_analysis, root_jailbreak_detection) used
to be byte-for-byte-logic-identical stubs that ignored `target` entirely
and instead did a DNS resolve + bare HTTP GET on `/`, always reporting
status "completed" — caught during this session's audit.

Mobile analysis is inherently FILE-based (.apk/.ipa) or DEVICE-based
(adb/libimobiledevice/frida) — no network-observable substitute exists the
way HTTP/TLS/DNS-based tools have one, except mobile_api_testing (which
genuinely talks to a backend API over HTTP). Each tool now either:
  - does real zipfile-based parsing of a genuine local .apk/.ipa file
    (APKs/IPAs are ZIP archives) and reports real findings from that
    parse, or
  - does real HTTP probing (mobile_api_testing), or
  - honestly reports STATUS_REQUIRES_HARDWARE / STATUS_OUT_OF_SCOPE /
    STATUS_FAILED with the real reason when its prerequisite (a valid
    local app file, or an attached device via frida/adb/idevice_id) isn't
    met, never fabricating findings.

These tests build synthetic-but-structurally-real APK/IPA fixtures (actual
ZIP archives, actual plistlib-written Info.plist) to prove the parsing is
real, and verify the device-dependent tools honestly degrade in this
environment (no frida/adb/idevice_id installed here) as well as when a
device is genuinely simulated as attached.
"""
from __future__ import annotations

import http.server
import plistlib
import sys
import threading
import types
import zipfile
from unittest.mock import MagicMock, patch

import pytest

from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    STATUS_REQUIRES_HARDWARE,
)
from nexus.tools.mobile import (
    android_analysis,
    apk_decompilation,
    cert_pinning_bypass,
    dynamic_instrumentation,
    ios_analysis,
    ipa_analysis,
    mobile_api_testing,
    mobile_malware_analysis,
    root_jailbreak_detection,
)

_OLD_FAKE_MARKERS = ("dns resolve", "bare http get")


# ── fixtures: synthetic-but-real APK / IPA archives ─────────────────────

def _build_apk(path, *, debuggable=True, dangerous_perms=True, native_lib=True, netsec_config=True):
    perms = ""
    if dangerous_perms:
        perms = (
            '<uses-permission android:name="android.permission.SEND_SMS"/>'
            '<uses-permission android:name="android.permission.INTERNET"/>'
            '<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>'
        )
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.test">'
        f'<application {"android:debuggable=\"true\"" if debuggable else ""}></application>'
        f"{perms}"
        "</manifest>"
    )
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\x00placeholder\x00data")
        if native_lib:
            z.writestr("lib/armeabi-v7a/libfoo.so", b"\x7fELF-fake-native-lib")
        if netsec_config:
            z.writestr("res/xml/network_security_config.xml", "<network-security-config/>")
    return str(path)


def _build_ipa(path, *, ats_arbitrary_loads=True):
    plist_dict = {
        "CFBundleIdentifier": "com.example.testapp",
        "CFBundleName": "TestApp",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["testapp"]}],
        "UIBackgroundModes": ["fetch", "location"],
    }
    if ats_arbitrary_loads:
        plist_dict["NSAppTransportSecurity"] = {"NSAllowsArbitraryLoads": True}
    plist_bytes = plistlib.dumps(plist_dict)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/TestApp.app/Info.plist", plist_bytes)
        z.writestr("Payload/TestApp.app/TestApp", b"\xca\xfe\xba\xbe-fake-macho-binary")
    return str(path)


@pytest.fixture
def fake_apk(tmp_path):
    return _build_apk(tmp_path / "sample.apk")


@pytest.fixture
def fake_apk_clean(tmp_path):
    return _build_apk(tmp_path / "clean.apk", debuggable=False, dangerous_perms=False)


@pytest.fixture
def fake_ipa(tmp_path):
    return _build_ipa(tmp_path / "sample.ipa")


@pytest.fixture
def fake_ipa_clean(tmp_path):
    return _build_ipa(tmp_path / "clean.ipa", ats_arbitrary_loads=False)


# ── apk_decompilation / android_analysis: real zipfile parsing ─────────

def test_apk_decompilation_parses_real_apk_archive(fake_apk):
    result = apk_decompilation.run(fake_apk)
    assert result["status"] == STATUS_COMPLETED
    evidence_blob = str(result).lower()
    assert "classes.dex" in evidence_blob or "true" in evidence_blob
    assert result["metadata"]["has_classes_dex"] is True
    assert result["metadata"]["has_manifest"] is True
    assert result["metadata"]["native_libs"] == ["lib/armeabi-v7a/libfoo.so"]
    assert result["metadata"]["entry_count"] == 4


def test_apk_decompilation_out_of_scope_for_non_apk_target():
    result = apk_decompilation.run("example.com")
    assert result["status"] == STATUS_OUT_OF_SCOPE
    assert result["findings"] == []


def test_apk_decompilation_failed_on_corrupt_apk(tmp_path):
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"not a real zip file at all")
    result = apk_decompilation.run(str(bad))
    assert result["status"] == STATUS_FAILED
    assert "zip" in result["error"].lower() or "apk" in result["error"].lower()


def test_android_analysis_flags_debuggable_and_missing_netsec_config(tmp_path):
    apk = _build_apk(tmp_path / "risky.apk", debuggable=True, netsec_config=False)
    result = android_analysis.run(apk)
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("debuggable" in t.lower() for t in titles)
    assert any("network security config" in t.lower() for t in titles)
    assert result["metadata"]["has_network_security_config"] is False


def test_android_analysis_clean_apk_has_no_debuggable_finding(fake_apk_clean):
    result = android_analysis.run(fake_apk_clean)
    titles = [f["title"].lower() for f in result["findings"]]
    assert not any("is debuggable" in t for t in titles)


def test_android_analysis_out_of_scope_for_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.apk"
    result = android_analysis.run(str(missing))
    assert result["status"] == STATUS_OUT_OF_SCOPE


# ── ipa_analysis / ios_analysis: real zipfile + plistlib parsing ───────

def test_ipa_analysis_parses_real_ipa_and_plist(fake_ipa):
    result = ipa_analysis.run(fake_ipa)
    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["bundle_id"] == "com.example.testapp"
    assert result["metadata"]["info_plist_path"] == "Payload/TestApp.app/Info.plist"
    assert result["metadata"]["ats_arbitrary_loads"] is True
    titles = [f["title"] for f in result["findings"]]
    assert any("App Transport Security" in t for t in titles)


def test_ipa_analysis_no_ats_finding_when_disabled_flag_absent(fake_ipa_clean):
    result = ipa_analysis.run(fake_ipa_clean)
    assert result["metadata"]["ats_arbitrary_loads"] is False


def test_ipa_analysis_out_of_scope_for_non_ipa_target():
    result = ipa_analysis.run("192.168.1.5")
    assert result["status"] == STATUS_OUT_OF_SCOPE


def test_ipa_analysis_failed_on_corrupt_ipa(tmp_path):
    bad = tmp_path / "bad.ipa"
    bad.write_bytes(b"also not a zip")
    result = ipa_analysis.run(str(bad))
    assert result["status"] == STATUS_FAILED


def test_ios_analysis_flags_ats_and_url_schemes_and_bg_modes(fake_ipa):
    result = ios_analysis.run(fake_ipa)
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("App Transport Security disabled" in t for t in titles)
    assert any("URL schemes" in t for t in titles)
    assert any("Background modes" in t for t in titles)
    evidence_all = " ".join(f["evidence"] for f in result["findings"])
    assert "testapp" in evidence_all
    assert "fetch" in evidence_all and "location" in evidence_all


def test_ios_analysis_out_of_scope_for_non_ipa_target():
    result = ios_analysis.run("not-a-file")
    assert result["status"] == STATUS_OUT_OF_SCOPE


# ── mobile_malware_analysis: real dangerous-permission-combo detection ──

def test_mobile_malware_analysis_flags_sms_trojan_combo(fake_apk):
    result = mobile_malware_analysis.run(fake_apk)
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("Dangerous permission combination" in t for t in titles)
    high_findings = [f for f in result["findings"] if f["severity"] == "high"]
    assert high_findings


def test_mobile_malware_analysis_clean_apk_no_findings(fake_apk_clean):
    result = mobile_malware_analysis.run(fake_apk_clean)
    assert result["status"] == STATUS_NO_FINDINGS
    titles = [f["title"] for f in result["findings"]]
    assert any("No known dangerous permission" in t for t in titles)


def test_mobile_malware_analysis_flags_ats_disabled_on_ipa(fake_ipa):
    result = mobile_malware_analysis.run(fake_ipa)
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("ATS disabled" in t for t in titles)


def test_mobile_malware_analysis_out_of_scope_for_url_target():
    result = mobile_malware_analysis.run("https://example.com")
    assert result["status"] == STATUS_OUT_OF_SCOPE


# ── mobile_api_testing: real HTTP checks against a local test server ────

class _MobileApiTestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib method name
        if self.path == "/api":
            self.send_response(401)
        elif self.path in ("/", "/api/mobile"):
            self.send_response(200)
        else:
            self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):  # silence test server logging
        pass


@pytest.fixture
def local_test_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _MobileApiTestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_mobile_api_testing_real_http_probe_against_local_server(local_test_server):
    result = mobile_api_testing.run(local_test_server)
    assert result["status"] in (STATUS_COMPLETED, STATUS_NO_FINDINGS)

    probed = result["metadata"]["probed"]
    by_path_status = {p["url"].split(local_test_server, 1)[-1]: p.get("status") for p in probed}
    # Real server behaviour must be reflected verbatim, not fabricated.
    assert by_path_status["/api"] == 401
    assert by_path_status["/api/mobile"] == 200
    assert by_path_status["/api/v1"] == 404
    assert by_path_status["/api/v2"] == 404

    titles = [f["title"] for f in result["findings"]]
    assert any("version" in t.lower() for t in titles)
    assert any("Mobile-API-shaped endpoint responded" in t for t in titles)


def test_mobile_api_testing_out_of_scope_for_apk_target():
    result = mobile_api_testing.run("app.apk")
    assert result["status"] == STATUS_OUT_OF_SCOPE


def test_mobile_api_testing_failed_when_target_unreachable():
    # Port 1 is a privileged/reserved port almost certainly refused locally.
    result = mobile_api_testing.run("127.0.0.1:1")
    assert result["status"] == STATUS_FAILED


# ── cert_pinning_bypass / dynamic_instrumentation / root_jailbreak_detection:
#    honest requires-device degrade in this environment (no frida/adb/
#    idevice_id installed here — realistic), plus real behaviour when a
#    device is genuinely simulated as attached. ─────────────────────────

@pytest.mark.parametrize("module", [cert_pinning_bypass, dynamic_instrumentation])
def test_frida_backed_tools_require_hardware_when_frida_not_installed(module):
    with patch("importlib.util.find_spec", return_value=None):
        result = module.run("com.example.testapp")
    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert result["findings"] == []
    result_str = str(result).lower()
    for marker in _OLD_FAKE_MARKERS:
        assert marker not in result_str


def test_root_jailbreak_detection_requires_hardware_when_no_device(monkeypatch):
    with patch("shutil.which", return_value=None):
        result = root_jailbreak_detection.run("emulator-5554")
    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert result["findings"] == []


def test_cert_pinning_bypass_real_readonly_device_check_when_attached(monkeypatch):
    fake_status = {
        "frida_python_installed": True,
        "frida_ps_installed": True,
        "device_attached": True,
        "device_id": "emulator-5554",
        "device_name": "Android Emulator",
        "frida_version": "16.0.0",
        "error": "",
    }
    monkeypatch.setattr(cert_pinning_bypass, "frida_status", lambda: fake_status)
    result = cert_pinning_bypass.run("com.example.testapp")
    assert result["status"] == STATUS_COMPLETED
    assert "emulator-5554" in str(result)
    # Never claims to have actually performed the bypass injection.
    assert "not performed automatically" in str(result).lower() or "explicit" in str(result).lower()


def test_dynamic_instrumentation_real_process_enum_when_device_attached(monkeypatch):
    fake_status = {
        "frida_python_installed": True,
        "frida_ps_installed": True,
        "device_attached": True,
        "device_id": "emulator-5554",
        "device_name": "Android Emulator",
        "frida_version": "16.0.0",
        "error": "",
    }
    monkeypatch.setattr(dynamic_instrumentation, "frida_status", lambda: fake_status)

    # MagicMock's `name=` kwarg sets the mock's own repr, not an attribute,
    # so set .name explicitly after construction.
    fake_proc1 = MagicMock(pid=100)
    fake_proc1.name = "com.example.testapp"
    fake_proc2 = MagicMock(pid=200)
    fake_proc2.name = "system_server"
    fake_device = MagicMock()
    fake_device.enumerate_processes.return_value = [fake_proc1, fake_proc2]
    fake_frida = types.ModuleType("frida")
    fake_frida.__spec__ = object()
    fake_frida.get_usb_device = MagicMock(return_value=fake_device)

    with patch.dict(sys.modules, {"frida": fake_frida}):
        result = dynamic_instrumentation.run("com.example.testapp")

    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["processes"] == [
        {"pid": 100, "name": "com.example.testapp"},
        {"pid": 200, "name": "system_server"},
    ]
    assert any("com.example.testapp" in f["evidence"] for f in result["findings"])


def test_root_jailbreak_detection_real_minimal_check_when_adb_device_connected_rooted(monkeypatch):
    monkeypatch.setattr(root_jailbreak_detection, "adb_status", lambda: {
        "adb_installed": True, "device_connected": True,
        "devices": ["emulator-5554"], "raw_output": "emulator-5554\tdevice", "error": "",
    })
    monkeypatch.setattr(root_jailbreak_detection, "idevice_status", lambda: {
        "idevice_id_installed": False, "device_connected": False, "devices": [],
        "error": "idevice_id not found",
    })

    def fake_run(cmd, **kwargs):
        proc = MagicMock()
        if cmd == ["adb", "shell", "which su"]:
            proc.stdout = "/system/xbin/su\n"
        elif cmd == ["adb", "shell", "getprop ro.build.tags"]:
            proc.stdout = "test-keys\n"
        else:
            proc.stdout = ""
        return proc

    monkeypatch.setattr(root_jailbreak_detection.subprocess, "run", fake_run)
    result = root_jailbreak_detection.run("emulator-5554")
    assert result["status"] == STATUS_COMPLETED
    assert result["findings"][0]["severity"] == "high"
    assert "test-keys" in result["findings"][0]["evidence"]


def test_root_jailbreak_detection_real_minimal_check_when_adb_device_connected_clean(monkeypatch):
    monkeypatch.setattr(root_jailbreak_detection, "adb_status", lambda: {
        "adb_installed": True, "device_connected": True,
        "devices": ["emulator-5554"], "raw_output": "emulator-5554\tdevice", "error": "",
    })
    monkeypatch.setattr(root_jailbreak_detection, "idevice_status", lambda: {
        "idevice_id_installed": False, "device_connected": False, "devices": [],
        "error": "idevice_id not found",
    })

    def fake_run(cmd, **kwargs):
        proc = MagicMock()
        if cmd == ["adb", "shell", "which su"]:
            proc.stdout = "su: not found\n"
        elif cmd == ["adb", "shell", "getprop ro.build.tags"]:
            proc.stdout = "release-keys\n"
        else:
            proc.stdout = ""
        return proc

    monkeypatch.setattr(root_jailbreak_detection.subprocess, "run", fake_run)
    result = root_jailbreak_detection.run("emulator-5554")
    assert result["status"] == STATUS_NO_FINDINGS
    assert result["findings"][0]["severity"] == "info"


# ── never fabricate: guard against the old DNS+HTTP stub pattern ───────

@pytest.mark.parametrize("module,target", [
    (cert_pinning_bypass, "com.example.app"),
    (dynamic_instrumentation, "com.example.app"),
    (root_jailbreak_detection, "emulator-5554"),
])
def test_device_tools_never_report_completed_without_a_real_device(module, target):
    with patch("importlib.util.find_spec", return_value=None), patch("shutil.which", return_value=None):
        result = module.run(target)
    assert result["status"] != "completed"
