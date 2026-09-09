"""Real bugs confirmed by this session's audit, fixed here:
- iot.firmware_extraction was byte-for-byte identical to
  iot.smart_device_assessment (a port scan) despite the name.
- ai_security.llm_prompt_injection_testing only worked on local AI-model
  files, never on the domain/IP/URL target type it's registered to accept.
- sarif_export.py's artifactLocation.uri wasn't spec-valid for bare
  host:port affected_asset values.
- generator.py's section numbers skipped when an optional section (asset
  inventory / verification / MITRE / attack chains) was absent.
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus.reporting.exporters.sarif_export import _as_uri
from nexus.reporting.generator import ReportGenerator


# ── iot.firmware_extraction ──────────────────────────────────────────────

def test_firmware_extraction_reports_exposed_firmware_endpoint(monkeypatch):
    from nexus.tools.iot import firmware_extraction

    def fake_probe(target, path, timeout=5):
        if path == "/firmware.bin":
            return {"path": path, "url": f"http://{target}{path}", "status": 200,
                     "content_type": "application/octet-stream", "content_length": "1024"}
        return None

    monkeypatch.setattr(firmware_extraction, "_probe_path", fake_probe)
    monkeypatch.setattr("socket.gethostbyname", lambda t: "10.0.0.5")

    result = firmware_extraction.run("device.example.com")

    assert result["status"] == "completed"
    joined = "\n".join(result["findings"])
    assert "firmware.bin" in joined
    assert "exposed firmware download" in joined


def test_firmware_extraction_no_endpoints_found(monkeypatch):
    from nexus.tools.iot import firmware_extraction

    monkeypatch.setattr(firmware_extraction, "_probe_path", lambda *a, **kw: None)
    monkeypatch.setattr("socket.gethostbyname", lambda t: "10.0.0.5")

    result = firmware_extraction.run("device.example.com")
    assert any("No common firmware-update endpoints found" in f for f in result["findings"])


def test_firmware_extraction_findings_differ_from_smart_device_assessment(monkeypatch):
    """The old bug: these two tools were byte-for-byte identical port
    scanners. Confirm firmware_extraction no longer does a port scan at
    all — it does HTTP path probing instead."""
    from nexus.tools.iot import firmware_extraction
    import inspect

    source = inspect.getsource(firmware_extraction)
    assert "create_connection" not in source  # no more port-scanning logic
    assert "_FIRMWARE_PATHS" in source


# ── ai_security.llm_prompt_injection_testing ─────────────────────────────

def test_llm_prompt_injection_finds_live_chat_endpoint(monkeypatch):
    from nexus.tools.ai_security import llm_prompt_injection_testing as mod

    def fake_probe(target, path, timeout=5):
        if path == "/v1/chat/completions":
            return {"path": path, "url": f"http://{target}{path}", "status": 200, "content_type": "application/json"}
        return None

    monkeypatch.setattr(mod, "_probe_endpoint", fake_probe)
    monkeypatch.setattr(mod, "_attempt_canary_injection", lambda url, canary, timeout=6: (False, "mocked, no attempt"))

    result = mod.run("chatbot.example.com")

    assert result["status"] == "completed"
    assert any("Possible LLM chat API endpoint found" in f for f in result["findings"])


def test_llm_prompt_injection_detects_successful_canary_injection(monkeypatch):
    from nexus.tools.ai_security import llm_prompt_injection_testing as mod

    def fake_probe(target, path, timeout=5):
        if path == "/api/chat":
            return {"path": path, "url": f"http://{target}{path}", "status": 200, "content_type": "application/json"}
        return None

    captured = {}

    def fake_canary_injection(url, canary, timeout=6):
        captured["canary"] = canary
        return True, "canary token echoed back verbatim — endpoint may be susceptible to prompt injection"

    monkeypatch.setattr(mod, "_probe_endpoint", fake_probe)
    monkeypatch.setattr(mod, "_attempt_canary_injection", fake_canary_injection)

    result = mod.run("chatbot.example.com")

    assert captured["canary"]
    joined = "\n".join(result["findings"])
    assert "echoed back verbatim" in joined
    assert "may be susceptible to prompt injection" in joined


def test_llm_prompt_injection_no_endpoints_falls_back_cleanly(monkeypatch):
    from nexus.tools.ai_security import llm_prompt_injection_testing as mod

    monkeypatch.setattr(mod, "_probe_endpoint", lambda *a, **kw: None)
    result = mod.run("plain-website.example.com")
    assert any("No common LLM chat API endpoints found" in f for f in result["findings"])


def test_llm_prompt_injection_local_model_file_path_still_works(monkeypatch):
    """The old (only) code path — confirm it still works as a secondary
    check, not removed."""
    from nexus.tools.ai_security import llm_prompt_injection_testing as mod

    monkeypatch.setattr(mod, "_probe_endpoint", lambda *a, **kw: None)
    with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
        f.write(b"fake model bytes")
        path = f.name
    try:
        result = mod.run(path)
        joined = "\n".join(result["findings"])
        assert "AI model file detected" in joined
        assert ".onnx" in joined
    finally:
        Path(path).unlink(missing_ok=True)


# ── sarif_export.py ───────────────────────────────────────────────────────

def test_sarif_uri_wraps_bare_host_port():
    assert _as_uri("10.0.0.1:22") == "asset://10.0.0.1:22"


def test_sarif_uri_passes_through_existing_scheme():
    assert _as_uri("https://example.com/path") == "https://example.com/path"


def test_sarif_uri_handles_empty_asset():
    assert _as_uri("") == "asset://unknown"


# ── generator.py section numbering ───────────────────────────────────────

def test_report_section_numbers_are_contiguous_with_no_optional_sections():
    report = ReportGenerator().generate([], target="example.com", mission_id="m1")
    headings = [line for line in report.splitlines() if line.startswith("## ")]
    numbers = [int(h.split(".", 1)[0].removeprefix("## ")) for h in headings]
    assert numbers == list(range(1, len(numbers) + 1))


def test_report_section_numbers_are_contiguous_with_all_optional_sections():
    findings = [
        {"id": "F-1", "title": "SQLi", "severity": "critical", "affected_asset": "host-a",
         "tool": "webapp.sqli_scan", "verification_status": "verified",
         "mitre_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]},
        {"id": "CHAIN-001", "title": "Attack chain: host-a -> host-b", "severity": "high",
         "affected_asset": "host-a", "kind": "synthetic_chain", "chain_assets": ["host-a", "host-b"]},
    ]
    report = ReportGenerator().generate(findings, target="example.com", mission_id="m2")
    headings = [line for line in report.splitlines() if line.startswith("## ")]
    numbers = [int(h.split(".", 1)[0].removeprefix("## ")) for h in headings]
    assert numbers == list(range(1, len(numbers) + 1))
    # With findings present, more sections should appear than the empty case.
    assert len(numbers) > 9
