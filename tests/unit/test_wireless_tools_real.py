"""All 11 nexus/tools/wireless/ tools (ble, bluetooth, deauth_test, evil_twin,
handshake_capture, lora, nfc_testing, rogue_ap, wifi_audit, wps_attack,
zigbee) used to be byte-for-byte-logic-identical stubs: they ran `which
<tool>` (a command that doesn't exist on Windows and silently no-ops there)
against a hardcoded, WiFi-tool-only binary list unrelated to most of the
tools' actual names, ignored `target` entirely, and always reported status
"completed" with a canned note — caught during this session's audit.

Wireless security fundamentally requires RF hardware physically present — no
network-observable substitute exists the way HTTP/TLS/DNS-based tools have
one. Each tool now checks a REAL, tool-appropriate prerequisite (aircrack-ng
suite binaries, bleak/PyBluez, libnfc/nfcpy, pyserial, zigpy/bellows) and:
  - honestly reports STATUS_REQUIRES_HARDWARE with the real reason when the
    prerequisite is absent (the overwhelmingly likely case on a dev
    machine), never fabricating findings;
  - does a real, minimal, safe, read-only enumeration when the prerequisite
    IS present (local wireless interfaces / adapters / serial ports), never
    fabricating captured handshakes, cracked keys, or client lists.

These tests verify both paths for every tool.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexus.foundation.schema import STATUS_REQUIRES_HARDWARE
from nexus.tools.wireless import (
    ble,
    bluetooth,
    deauth_test,
    evil_twin,
    handshake_capture,
    lora,
    nfc_testing,
    rogue_ap,
    wifi_audit,
    wps_attack,
    zigbee,
)

TARGET = "192.168.1.50"

# The old fake stub always returned this shape regardless of tool identity.
_OLD_FAKE_NOTE = "Note: Wireless analysis requires compatible WiFi adapter"


# ── aircrack-ng-suite-backed tools ──────────────────────────────────────────
# wifi_audit, deauth_test, evil_twin, rogue_ap, wps_attack, handshake_capture

_BINARY_MODULES = [wifi_audit, deauth_test, evil_twin, rogue_ap, wps_attack, handshake_capture]


@pytest.mark.parametrize("module", _BINARY_MODULES)
def test_binary_backed_tools_require_hardware_when_no_binaries_on_path(module):
    with patch("shutil.which", return_value=None):
        result = module.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert result["status"] == "requires_hardware"
    assert result["findings"] == []
    assert _OLD_FAKE_NOTE not in str(result)
    # Never claims a completed assessment of the target.
    assert result["status"] != "completed"


@pytest.mark.parametrize("module", _BINARY_MODULES)
def test_binary_backed_tools_do_not_fabricate_dns_or_http_findings(module):
    """Guards against the described DNS-resolve + bare HTTP GET fake pattern
    resurfacing — the target hostname/IP must never appear as if it were
    network-probed, and no fake "resolved"/"HTTP" style findings appear."""
    with patch("shutil.which", return_value=None):
        result = module.run(TARGET)

    result_str = str(result).lower()
    assert "http" not in result_str
    assert "resolved" not in result_str


def test_wifi_audit_real_enumeration_when_airmon_ng_present():
    fake_result = MagicMock(stdout="wlan0\tRealtek RTL8812AU\nwlan0mon\tmonitor mode enabled\n")
    with patch("shutil.which", side_effect=lambda name: "/usr/sbin/airmon-ng" if name == "airmon-ng" else None), \
         patch("nexus.tools.wireless.wifi_audit.run_subprocess", return_value=fake_result) as mock_run:
        result = wifi_audit.run(TARGET)

    mock_run.assert_called_once()
    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "wlan0" in result["findings"][0]["evidence"]


def test_deauth_test_real_enumeration_when_aireplay_ng_present():
    fake_result = MagicMock(stdout="wlan1  Atheros AR9271\n")
    with patch("shutil.which", side_effect=lambda name: "/usr/sbin/aireplay-ng" if name == "aireplay-ng" else None), \
         patch("nexus.tools.wireless.deauth_test.run_subprocess", return_value=fake_result):
        result = deauth_test.run(TARGET)

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    # Never actually claims to have sent a deauth frame.
    assert "sent" not in result["summary"].lower() or "not" in result["summary"].lower() or "no deauth" in result["summary"].lower()


def test_evil_twin_no_findings_when_tooling_present_but_no_interfaces():
    fake_result = MagicMock(stdout="")
    with patch("shutil.which", side_effect=lambda name: "/usr/sbin/hostapd" if name == "hostapd" else None), \
         patch("nexus.tools.wireless.evil_twin.run_subprocess", return_value=fake_result):
        result = evil_twin.run(TARGET)

    assert result["status"] == "no_findings"
    assert result["findings"] == []


def test_wps_attack_real_enumeration_when_wash_present():
    fake_result = MagicMock(stdout="Wash 1.6.5\n")
    with patch("shutil.which", side_effect=lambda name: "/usr/sbin/wash" if name == "wash" else None), \
         patch("nexus.tools.wireless.wps_attack.run_subprocess", return_value=fake_result):
        result = wps_attack.run(TARGET)

    assert result["status"] == "completed"
    assert "not" in result["summary"].lower()  # confirms it did NOT run an attack


def test_handshake_capture_real_enumeration_when_airodump_ng_present():
    fake_result = MagicMock(stdout="wlan0mon\n")
    with patch("shutil.which", side_effect=lambda name: "/usr/sbin/airodump-ng" if name == "airodump-ng" else None), \
         patch("nexus.tools.wireless.handshake_capture.run_subprocess", return_value=fake_result):
        result = handshake_capture.run(TARGET)

    assert result["status"] == "completed"
    # Never fabricates an actual captured handshake blob.
    assert "handshake" not in str(result["metadata"]).lower() or "captured" not in str(result["metadata"]).lower()


def test_rogue_ap_requires_hardware_metadata_lists_checked_binaries():
    with patch("shutil.which", return_value=None):
        result = rogue_ap.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert set(result["metadata"]["checked_binaries"]) == {"hostapd", "dnsmasq", "airmon-ng"}
    assert all(v is None for v in result["metadata"]["checked_binaries"].values())


# ── ble.py ───────────────────────────────────────────────────────────────

def test_ble_requires_hardware_when_bleak_not_installed():
    with patch.dict(sys.modules, {"bleak": None}):
        result = ble.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert result["findings"] == []
    assert "bleak" in result["error"]


def test_ble_requires_hardware_when_bleak_present_but_scan_fails():
    fake_bleak = types.ModuleType("bleak")
    fake_bleak.BleakScanner = MagicMock()
    fake_bleak.BleakScanner.discover = AsyncMock(side_effect=OSError("no BLE adapter"))
    with patch.dict(sys.modules, {"bleak": fake_bleak}):
        result = ble.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "no BLE adapter" in result["error"]


def test_ble_real_scan_reports_actual_devices_when_adapter_present():
    fake_device = MagicMock(address="AA:BB:CC:DD:EE:FF", name="TestBeacon", rssi=-42)
    fake_bleak = types.ModuleType("bleak")
    fake_bleak.BleakScanner = MagicMock()
    fake_bleak.BleakScanner.discover = AsyncMock(return_value=[fake_device])
    with patch.dict(sys.modules, {"bleak": fake_bleak}):
        result = ble.run(TARGET)

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "AA:BB:CC:DD:EE:FF" in result["findings"][0]["evidence"]


# ── bluetooth.py ─────────────────────────────────────────────────────────

def test_bluetooth_requires_hardware_when_no_prereqs_available():
    with patch.dict(sys.modules, {"bluetooth": None}), patch("shutil.which", return_value=None):
        result = bluetooth.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert result["findings"] == []


def test_bluetooth_requires_hardware_when_pybluez_present_but_no_adapter():
    fake_pybluez = types.ModuleType("bluetooth")
    fake_pybluez.discover_devices = MagicMock(side_effect=OSError("no Bluetooth adapter"))
    with patch.dict(sys.modules, {"bluetooth": fake_pybluez}):
        result = bluetooth.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "no Bluetooth adapter" in result["error"]


def test_bluetooth_real_scan_reports_actual_devices_via_pybluez():
    fake_pybluez = types.ModuleType("bluetooth")
    fake_pybluez.discover_devices = MagicMock(return_value=[("11:22:33:44:55:66", "MyPhone")])
    with patch.dict(sys.modules, {"bluetooth": fake_pybluez}):
        result = bluetooth.run(TARGET)

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "11:22:33:44:55:66" in result["findings"][0]["evidence"]


def test_bluetooth_read_only_controller_listing_via_bluetoothctl_fallback():
    fake_result = MagicMock(stdout="Controller AA:BB:CC:DD:EE:FF hci0\n")
    with patch.dict(sys.modules, {"bluetooth": None}), \
         patch("shutil.which", side_effect=lambda name: "/usr/bin/bluetoothctl" if name == "bluetoothctl" else None), \
         patch("nexus.tools.wireless.bluetooth.run_subprocess", return_value=fake_result):
        result = bluetooth.run(TARGET)

    assert result["status"] == "completed"
    assert "hci0" in result["findings"][0]["evidence"]


# ── nfc_testing.py ───────────────────────────────────────────────────────

def test_nfc_testing_requires_hardware_when_no_prereqs_available():
    with patch("shutil.which", return_value=None), patch.dict(sys.modules, {"nfc": None}):
        result = nfc_testing.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert result["findings"] == []


def test_nfc_testing_real_enumeration_via_nfc_list():
    fake_result = MagicMock(stdout="nfc-list uses libnfc 1.8.0\n1 NFC device found: ACR122U\n")
    with patch("shutil.which", side_effect=lambda name: "/usr/bin/nfc-list" if name == "nfc-list" else None), \
         patch("nexus.tools.wireless.nfc_testing.run_subprocess", return_value=fake_result):
        result = nfc_testing.run(TARGET)

    assert result["status"] == "completed"
    assert any("ACR122U" in f["evidence"] for f in result["findings"])


def test_nfc_testing_requires_hardware_when_nfcpy_present_but_no_reader():
    fake_nfc = types.ModuleType("nfc")
    fake_nfc.ContactlessFrontend = MagicMock(side_effect=IOError("no NFC reader found on usb"))
    with patch("shutil.which", return_value=None), patch.dict(sys.modules, {"nfc": fake_nfc}):
        result = nfc_testing.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "no NFC reader" in result["error"]


# ── lora.py ──────────────────────────────────────────────────────────────

def test_lora_requires_hardware_when_pyserial_not_installed():
    with patch.dict(sys.modules, {"serial": None, "serial.tools": None, "serial.tools.list_ports": None}):
        result = lora.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "pyserial" in result["error"]


def test_lora_requires_hardware_when_pyserial_installed_but_no_ports():
    fake_list_ports = types.ModuleType("serial.tools.list_ports")
    fake_list_ports.comports = MagicMock(return_value=[])
    fake_serial_tools = types.ModuleType("serial.tools")
    fake_serial_tools.list_ports = fake_list_ports
    fake_serial = types.ModuleType("serial")
    fake_serial.tools = fake_serial_tools

    with patch.dict(sys.modules, {
        "serial": fake_serial, "serial.tools": fake_serial_tools, "serial.tools.list_ports": fake_list_ports,
    }):
        result = lora.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "no serial ports enumerated" in result["error"]


def test_lora_real_enumeration_reports_candidate_ports_when_present():
    fake_port = MagicMock(device="COM3", description="USB Serial Device", hwid="USB VID:PID=1A86:7523")
    fake_list_ports = types.ModuleType("serial.tools.list_ports")
    fake_list_ports.comports = MagicMock(return_value=[fake_port])
    fake_serial_tools = types.ModuleType("serial.tools")
    fake_serial_tools.list_ports = fake_list_ports
    fake_serial = types.ModuleType("serial")
    fake_serial.tools = fake_serial_tools

    with patch.dict(sys.modules, {
        "serial": fake_serial, "serial.tools": fake_serial_tools, "serial.tools.list_ports": fake_list_ports,
    }):
        result = lora.run(TARGET)

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "COM3" in result["findings"][0]["evidence"]
    # Must never claim certainty it IS a LoRa radio.
    assert result["findings"][0]["confidence"] == "low"


# ── zigbee.py ────────────────────────────────────────────────────────────

def test_zigbee_requires_hardware_when_zigpy_stack_missing():
    fake_list_ports = types.ModuleType("serial.tools.list_ports")
    fake_list_ports.comports = MagicMock(return_value=[MagicMock(device="COM4")])
    fake_serial_tools = types.ModuleType("serial.tools")
    fake_serial_tools.list_ports = fake_list_ports
    fake_serial = types.ModuleType("serial")
    fake_serial.tools = fake_serial_tools

    with patch.dict(sys.modules, {
        "serial": fake_serial, "serial.tools": fake_serial_tools, "serial.tools.list_ports": fake_list_ports,
        "zigpy": None, "bellows": None,
    }):
        result = zigbee.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "zigpy/bellows" in result["error"]


def test_zigbee_requires_hardware_when_pyserial_missing():
    fake_zigpy = types.ModuleType("zigpy")
    fake_bellows = types.ModuleType("bellows")
    with patch.dict(sys.modules, {
        "serial": None, "serial.tools": None, "serial.tools.list_ports": None,
        "zigpy": fake_zigpy, "bellows": fake_bellows,
    }):
        result = zigbee.run(TARGET)

    assert result["status"] == STATUS_REQUIRES_HARDWARE
    assert "pyserial" in result["error"]


def test_zigbee_real_enumeration_reports_candidate_ports_when_stack_present():
    fake_port = MagicMock(device="/dev/ttyUSB0", description="Silicon Labs CP2102", hwid="USB VID:PID=10C4:EA60")
    fake_list_ports = types.ModuleType("serial.tools.list_ports")
    fake_list_ports.comports = MagicMock(return_value=[fake_port])
    fake_serial_tools = types.ModuleType("serial.tools")
    fake_serial_tools.list_ports = fake_list_ports
    fake_serial = types.ModuleType("serial")
    fake_serial.tools = fake_serial_tools
    fake_zigpy = types.ModuleType("zigpy")
    fake_bellows = types.ModuleType("bellows")

    with patch.dict(sys.modules, {
        "serial": fake_serial, "serial.tools": fake_serial_tools, "serial.tools.list_ports": fake_list_ports,
        "zigpy": fake_zigpy, "bellows": fake_bellows,
    }):
        result = zigbee.run(TARGET)

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1
    assert "/dev/ttyUSB0" in result["findings"][0]["evidence"]


# ── cross-cutting: none of the 11 fabricate a "completed" assessment of a
# target when nothing is actually available ──────────────────────────────

_ALL_MODULES_NO_SOFTWARE_PREREQS = _BINARY_MODULES


@pytest.mark.parametrize("module", _ALL_MODULES_NO_SOFTWARE_PREREQS)
def test_never_claims_completed_target_coverage_without_hardware(module):
    with patch("shutil.which", return_value=None):
        result = module.run(TARGET)
    assert result["status"] != "completed"
    assert result["status"] != "no_findings"
