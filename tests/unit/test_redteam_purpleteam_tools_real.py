"""
Tests proving the 14 formerly-fake red_team/purple_team stub tools now do
REAL, safe, MITRE-ATT&CK-mapped work instead of the old identical
"DNS resolve + bare HTTP GET on /" stub logic.

Covers:
- Every tool returns real MITRE ATT&CK technique IDs (T\\d{4} pattern).
- discovery_simulation and control_validation genuinely perform real
  HTTP/network work against a local test HTTP server (not simulated).
- red_blue_collaboration / rule_improvement honestly degrade with
  tool-specific (not templated) explanations when required real input is
  absent, and perform genuine cross-referencing when given real input.
"""
from __future__ import annotations

import http.server
import json
import re
import threading

import pytest

from nexus.foundation.config import config

# Ensure every tool module registers itself with tool_registry, and every
# tool these modules call via tool_registry.run() is also registered.
import nexus.tools.network.host_discovery  # noqa: F401
import nexus.tools.network.port_scan  # noqa: F401
import nexus.tools.blue_team.canary_token_deployment  # noqa: F401

import nexus.tools.red_team.initial_access_simulation as initial_access_simulation
import nexus.tools.red_team.credential_access_simulation as credential_access_simulation
import nexus.tools.red_team.discovery_simulation as discovery_simulation
import nexus.tools.red_team.lateral_movement_simulation as lateral_movement_simulation
import nexus.tools.red_team.persistence_simulation as persistence_simulation
import nexus.tools.red_team.defense_evasion_simulation as defense_evasion_simulation
import nexus.tools.red_team.exfiltration_simulation as exfiltration_simulation
import nexus.tools.red_team.impact_simulation as impact_simulation
import nexus.tools.red_team.command_and_control as command_and_control
import nexus.tools.purple_team.attck_validation as attck_validation
import nexus.tools.purple_team.control_validation as control_validation
import nexus.tools.purple_team.detection_testing as detection_testing
import nexus.tools.purple_team.red_blue_collaboration as red_blue_collaboration
import nexus.tools.purple_team.rule_improvement as rule_improvement
from nexus.tools.registry import tool_registry

TECHNIQUE_RE = re.compile(r"T\d{4}")


# ── Local real HTTP test target ─────────────────────────────────────────────

class _TestSiteHandler(http.server.BaseHTTPRequestHandler):
    """A tiny, real local HTTP server: a login form on `/`, a `/login` POST
    endpoint that never locks out, and one real (partial) security header
    set — enough surface for the tools under test to genuinely observe."""

    server_version = "NexusTestSite/1.0"

    def _send(self, code: int, body: bytes, extra_headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/"):
            body = (
                b"<html><body><h1>Portal</h1>"
                b'<form action="/login" method="post">'
                b'<input type="text" name="username">'
                b'<input type="password" name="password">'
                b"</form></body></html>"
            )
            # Real, partial control set: X-Frame-Options present, but CSP,
            # HSTS, X-Content-Type-Options, Referrer-Policy all genuinely
            # absent — gives control_validation a real present/missing mix.
            self._send(200, body, {"X-Frame-Options": "DENY", "Server": "NexusTestSite"})
            return
        self._send(404, b"not found")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/login":
            # Never locks out, always "invalid credentials" — real, observable behavior.
            self._send(200, b"invalid credentials")
            return
        self._send(404, b"not found")

    def log_message(self, format, *args):  # noqa: A002 - silence test server logging
        pass


@pytest.fixture(scope="module")
def local_site():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TestSiteHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {"host": "127.0.0.1", "port": port, "target": f"127.0.0.1:{port}", "url": f"http://127.0.0.1:{port}/"}
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture()
def authorized(monkeypatch):
    """Some of these tools call other registered tools via
    tool_registry.run(), which enforces the full guardrail chain (including
    LegalGuard). Real engagements set this; tests must too."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost,127.0.0.1,::1")
    yield


def _all_text(result: dict) -> str:
    return json.dumps(result, default=str)


# ── Registration sanity ─────────────────────────────────────────────────────

_ALL_TOOL_NAMES = [
    "red_team.initial_access_simulation",
    "red_team.credential_access_simulation",
    "red_team.discovery_simulation",
    "red_team.lateral_movement_simulation",
    "red_team.persistence_simulation",
    "red_team.defense_evasion_simulation",
    "red_team.exfiltration_simulation",
    "red_team.impact_simulation",
    "red_team.command_and_control",
    "purple_team.attck_validation",
    "purple_team.control_validation",
    "purple_team.detection_testing",
    "purple_team.red_blue_collaboration",
    "purple_team.rule_improvement",
]


def test_all_14_tools_registered():
    registered = tool_registry.list_tools()
    for name in _ALL_TOOL_NAMES:
        assert name in registered, f"{name} not registered"
        assert registered[name]["status"] == "completed"


# ── Real MITRE-mapped simulations (12 tools) ────────────────────────────────

def test_initial_access_simulation_real_and_mitre_mapped(local_site):
    result = initial_access_simulation.run(local_site["target"])
    assert result["status"] == "completed"
    assert TECHNIQUE_RE.search(_all_text(result))
    titles = [f["title"] for f in result["findings"]]
    assert any("T1190" in t for t in titles)
    # Login form on the real local server was genuinely observed -> T1078.
    assert any("T1078" in t for t in titles)
    assert result["metadata"]["http_reachable"] is True


def test_credential_access_simulation_bounded_real_probe(local_site):
    result = credential_access_simulation.run(local_site["target"])
    assert result["status"] == "completed"
    assert TECHNIQUE_RE.search(_all_text(result))
    assert result["metadata"]["login_endpoint_found"] is True
    # Bounded: never more than 3 real auth attempts sent.
    assert 0 < result["metadata"]["auth_attempts_sent"] <= 3
    titles = [f["title"] for f in result["findings"]]
    assert any("T1110" in t for t in titles)
    assert any("T1003" in t for t in titles)


def test_discovery_simulation_genuinely_real_network_work(local_site, authorized):
    result = discovery_simulation.run(
        local_site["host"], ports=[local_site["port"]],
    )
    assert result["status"] == "completed"
    assert TECHNIQUE_RE.search(_all_text(result))
    # Real sub-tool calls actually ran.
    assert result["metadata"]["port_scan"]["status"] in ("completed", "no_findings")
    assert result["metadata"]["host_discovery"]["status"] in ("completed", "no_findings")
    # The real local server's port must show up as genuinely discovered open.
    evidence_blob = _all_text(result)
    assert f"Open port {local_site['port']}" in evidence_blob
    assert "T1046" in evidence_blob
    assert "T1018" in evidence_blob
    assert "T1082" in evidence_blob


def test_control_validation_genuinely_real_header_check(local_site):
    result = control_validation.run(local_site["target"])
    assert result["status"] == "completed"
    present = result["metadata"]["headers_present"]
    missing = result["metadata"]["headers_missing"]
    # Real, observed mix — not fabricated: X-Frame-Options really was sent,
    # Content-Security-Policy really was not.
    assert "X-Frame-Options" in present
    assert "Content-Security-Policy" in missing
    assert TECHNIQUE_RE.search(_all_text(result))


def test_detection_testing_real_canary_generation(local_site, authorized):
    result = detection_testing.run(local_site["host"])
    assert result["status"] == "completed"
    assert result["metadata"]["canaries_generated"] >= 4
    assert TECHNIQUE_RE.search(_all_text(result))


def test_attck_validation_real_cross_reference():
    findings = [
        {"title": "SQL injection found on /login endpoint", "tool": "webapp.sqli_test"},
        {"title": "Open port 3389 (RDP) on host", "tool": "network.port_scan"},
    ]
    result = attck_validation.run("engagement-1", findings=findings)
    assert result["status"] == "completed"
    assert TECHNIQUE_RE.search(_all_text(result))
    assert "T1190" in result["metadata"]["covered_techniques"]
    assert "Initial Access" in result["metadata"]["covered_tactics"]
    # A real gap: nothing here maps to Impact.
    assert "Impact" in result["metadata"]["tactic_gaps"]


@pytest.mark.parametrize("mod, tactic_word", [
    (lateral_movement_simulation, "Lateral Movement"),
    (persistence_simulation, "Persistence"),
    (defense_evasion_simulation, "Defense Evasion"),
    (exfiltration_simulation, "Exfiltration"),
    (impact_simulation, "Impact"),
    (command_and_control, "Command and Control"),
])
def test_ttp_report_tools_real_mitre_mapped_and_deterministic(mod, tactic_word):
    result = mod.run("127.0.0.1", seed=42)
    assert result["status"] == "completed"
    assert TECHNIQUE_RE.search(_all_text(result))
    assert result["findings"], "expected at least one finding"
    for f in result["findings"]:
        assert tactic_word in f["title"] or tactic_word in f["evidence"]
    # Reproducible with the same seed.
    result2 = mod.run("127.0.0.1", seed=42)
    assert [f["title"] for f in result["findings"]] == [f["title"] for f in result2["findings"]]


def test_ttp_report_tools_are_genuinely_per_technique_not_templated():
    """The 6 detection-signal report tools must not share one templated
    paragraph — each technique's evidence should be specific to it."""
    modules = [
        lateral_movement_simulation, persistence_simulation, defense_evasion_simulation,
        exfiltration_simulation, impact_simulation, command_and_control,
    ]
    all_evidences: list[str] = []
    for mod in modules:
        result = mod.run("127.0.0.1", seed=1)
        for f in result["findings"]:
            all_evidences.append(f["evidence"])
    # No two techniques (across all 6 tactics) share identical evidence text.
    assert len(all_evidences) == len(set(all_evidences))


def test_lateral_movement_and_c2_include_real_port_reachability_context():
    result = lateral_movement_simulation.run("127.0.0.1", seed=7)
    assert "ports_checked" in result["metadata"]
    assert "ports_reachable" in result["metadata"]
    assert any("Real port reachability check" in f["evidence"] for f in result["findings"])

    result2 = command_and_control.run("127.0.0.1", seed=7)
    assert "ports_checked" in result2["metadata"]
    assert any("Real port reachability check" in f["evidence"] for f in result2["findings"])


# ── Honest degrade tools ────────────────────────────────────────────────────

def test_red_blue_collaboration_honest_degrade_when_no_data():
    result = red_blue_collaboration.run("engagement-1")
    assert result["status"] == "unavailable"
    assert "red_team_findings" in result["summary"]
    assert "blue_team_detections" in result["summary"]


def test_rule_improvement_honest_degrade_when_no_data():
    result = rule_improvement.run("engagement-1")
    assert result["status"] == "unavailable"
    assert "detection_rules" in result["summary"]
    assert "missed_techniques" in result["summary"] or "findings" in result["summary"]


def test_honest_degrade_explanations_are_tool_specific_not_templated():
    collab_result = red_blue_collaboration.run("engagement-1")
    rule_result = rule_improvement.run("engagement-1")
    assert collab_result["summary"] != rule_result["summary"]
    # Each explanation names ITS OWN required kwargs, not the other tool's.
    assert "detection_rules" not in collab_result["summary"]
    assert "red_team_findings" not in rule_result["summary"]


def test_red_blue_collaboration_partial_data_gives_specific_message():
    result = red_blue_collaboration.run("engagement-1", red_team_findings=[{"technique_id": "T1110"}])
    assert result["status"] == "unavailable"
    assert "blue_team_detections" in result["summary"]


def test_red_blue_collaboration_real_cross_reference_with_real_data():
    red = [
        {"title": "[MISSED] Credential Access: Brute Force (T1110)", "technique_id": "T1110"},
        {"title": "[DETECTED] Discovery: Network Service Discovery (T1046)", "technique_id": "T1046"},
    ]
    blue = [
        {"technique_id": "T1046", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    result = red_blue_collaboration.run("engagement-1", red_team_findings=red, blue_team_detections=blue)
    assert result["status"] == "completed"
    assert result["metadata"]["validated"] == ["T1046"]
    assert result["metadata"]["gaps"] == ["T1110"]


def test_rule_improvement_real_analysis_with_real_data():
    rules = [
        {"rule_id": "R-1", "technique_id": "T1046", "false_positive_rate": 0.02},
    ]
    missed = [
        {"technique_id": "T1110", "detection_hint": "auth log spike"},
    ]
    result = rule_improvement.run("engagement-1", detection_rules=rules, missed_techniques=missed)
    assert result["status"] == "completed"
    assert result["metadata"]["new_rules_needed"] == 1
    titles = [f["title"] for f in result["findings"]]
    assert any("T1110" in t and "New detection rule needed" in t for t in titles)


def test_rule_improvement_flags_missed_technique_with_existing_rule():
    rules = [{"rule_id": "R-1", "technique_id": "T1110", "false_positive_rate": 0.01}]
    missed = [{"technique_id": "T1110"}]
    result = rule_improvement.run("engagement-1", detection_rules=rules, missed_techniques=missed)
    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("Existing rule failed to fire" in t for t in titles)


# ── Old fake-stub behavior must be gone ─────────────────────────────────────

def test_tools_no_longer_share_identical_stub_logic():
    """The audit finding this fixes: all 14 tools were byte-for-byte
    logic-identical (DNS resolve + bare HTTP GET). Their real
    implementations must now differ."""
    import inspect
    sources = {
        name: inspect.getsource(mod.run)
        for name, mod in [
            ("initial_access", initial_access_simulation),
            ("credential_access", credential_access_simulation),
            ("discovery", discovery_simulation),
            ("lateral_movement", lateral_movement_simulation),
            ("persistence", persistence_simulation),
            ("defense_evasion", defense_evasion_simulation),
            ("exfiltration", exfiltration_simulation),
            ("impact", impact_simulation),
            ("c2", command_and_control),
            ("attck_validation", attck_validation),
            ("control_validation", control_validation),
            ("detection_testing", detection_testing),
            ("red_blue_collaboration", red_blue_collaboration),
            ("rule_improvement", rule_improvement),
        ]
    }
    values = list(sources.values())
    assert len(set(values)) == len(values), "two tools still share identical run() source"
