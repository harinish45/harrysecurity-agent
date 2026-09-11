"""20 stub tools (appsec.cicd_security/dast/dependency_analysis/sca/
secure_code_review/threat_modeling, automation.ai_agent_development/
bash_automation/custom_tool_development/powershell_automation/
python_scripting/security_orchestration/soar_playbooks, iam.ad_iam/
ldap_testing/mfa_reviews/oauth_testing/pam_testing/saml_testing/
sso_testing) were byte-for-byte-logic-identical: a bare DNS resolve + a
bare HTTP GET on "/" regardless of tool name — caught during this
session's audit. Each now does real, tool-appropriate work (local manifest
parsing + OSV.dev lookups, real regex source/CI-config review, real
self-checks of this platform's own execution environment/registry, real
LDAP/SAML/OIDC network probes) or honestly degrades when the target/data
shape genuinely doesn't support real work, instead of fabricating a
"completed" result from an unrelated bare GET.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import pytest

from nexus.tools.appsec import (
    cicd_security,
    dast,
    dependency_analysis,
    sca,
    secure_code_review,
    threat_modeling,
)
from nexus.tools.automation import (
    ai_agent_development,
    bash_automation,
    custom_tool_development,
    powershell_automation,
    python_scripting,
    security_orchestration,
    soar_playbooks,
)
from nexus.tools.iam import (
    ad_iam,
    ldap_testing,
    mfa_reviews,
    oauth_testing,
    pam_testing,
    saml_testing,
    sso_testing,
)


# ═════════════════════════════════════════════════════════════════════════
# appsec.* — local manifest / source / CI-config review
# ═════════════════════════════════════════════════════════════════════════

def _fake_osv(name, version, ecosystem, timeout=10):
    if (name, version) == ("django", "1.4"):
        return [{"id": "GHSA-fake-0001", "summary": "CRITICAL: old Django vulnerability"}]
    return []


class TestDependencyAnalysisAndSca:
    """Real requirements.txt parsing + OSV.dev lookup (mocked)."""

    @pytest.mark.parametrize("module", [dependency_analysis, sca])
    def test_finds_known_vuln_in_pinned_requirement(self, module, tmp_path):
        (tmp_path / "requirements.txt").write_text("django==1.4\nrequests==2.31.0\n", encoding="utf-8")

        with patch("nexus.tools.appsec._manifest_scan.query_osv", side_effect=_fake_osv):
            result = module.run(str(tmp_path))

        assert result["status"] == "completed"
        assert len(result["findings"]) == 1
        assert "django==1.4" in result["findings"][0]["title"]
        assert result["findings"][0]["severity"] == "critical"
        assert result["metadata"]["packages_checked"] == 2
        assert result["metadata"]["vulnerable_packages"] == 1

    @pytest.mark.parametrize("module", [dependency_analysis, sca])
    def test_no_findings_when_all_packages_clean(self, module, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        with patch("nexus.tools.appsec._manifest_scan.query_osv", side_effect=_fake_osv):
            result = module.run(str(tmp_path))
        assert result["status"] == "no_findings"
        assert result["findings"] == []

    @pytest.mark.parametrize("module", [dependency_analysis, sca])
    def test_honest_degrade_on_non_manifest_target(self, module):
        result = module.run("not-a-real-path-or-domain-shaped-target")
        assert result["status"] == "out_of_scope"
        assert result["findings"] == []

    def test_parses_package_json_dependencies(self, tmp_path):
        pkg = {"dependencies": {"lodash": "^4.17.15"}, "devDependencies": {}}
        (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

        seen = []

        def fake_osv(name, version, ecosystem, timeout=10):
            seen.append((name, version, ecosystem))
            return []

        with patch("nexus.tools.appsec._manifest_scan.query_osv", side_effect=fake_osv):
            result = dependency_analysis.run(str(tmp_path))

        assert result["status"] == "no_findings"
        assert ("lodash", "4.17.15", "npm") in seen


class TestSecureCodeReview:
    """Real regex scan of local source files."""

    def test_detects_eval_usage(self, tmp_path):
        (tmp_path / "bad.py").write_text("x = eval(user_input)\n", encoding="utf-8")
        result = secure_code_review.run(str(tmp_path))
        assert result["status"] == "completed"
        titles = [f["title"] for f in result["findings"]]
        assert any("eval" in t.lower() for t in titles)

    def test_detects_hardcoded_password_and_shell_true(self, tmp_path):
        code = 'password = "hunter2super"\nsubprocess.run(cmd, shell=True)\n'
        (tmp_path / "bad.py").write_text(code, encoding="utf-8")
        result = secure_code_review.run(str(tmp_path))
        titles = " ".join(f["title"] for f in result["findings"])
        assert "password" in titles.lower()
        assert "shell=True" in titles

    def test_clean_file_reports_no_findings(self, tmp_path):
        (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        result = secure_code_review.run(str(tmp_path))
        assert result["status"] == "no_findings"
        assert result["findings"] == []

    def test_honest_degrade_on_non_local_target(self):
        result = secure_code_review.run("not-a-real-local-path-xyz")
        assert result["status"] == "out_of_scope"


class TestCicdSecurity:
    """Real regex review of CI config files."""

    def test_detects_pull_request_target_with_untrusted_checkout(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "on: pull_request_target\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v3\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n",
            encoding="utf-8",
        )
        result = cicd_security.run(str(tmp_path))
        assert result["status"] == "completed"
        titles = " ".join(f["title"] for f in result["findings"])
        assert "pull_request_target" in titles

    def test_detects_write_all_permissions(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text("permissions: write-all\njobs:\n  build:\n    steps: []\n", encoding="utf-8")
        result = cicd_security.run(str(tmp_path))
        titles = " ".join(f["title"] for f in result["findings"])
        assert "write-all" in titles

    def test_no_ci_files_found(self, tmp_path):
        result = cicd_security.run(str(tmp_path))
        assert result["status"] == "no_findings"

    def test_honest_degrade_on_non_local_target(self):
        result = cicd_security.run("not-a-real-local-path-xyz")
        assert result["status"] == "out_of_scope"


class TestDast:
    """Real composite dispatch into webapp.xss/sqli/ssrf via tool_registry."""

    def test_aggregates_subtool_findings(self, monkeypatch):
        from nexus.tools.registry import tool_registry

        def fake_xss(target, **kwargs):
            return {
                "tool": "webapp.xss", "target": target, "status": "completed",
                "findings": [{"title": "Reflected XSS", "severity": "high", "confidence": "high",
                               "affected_asset": target, "evidence": "e", "remediation": "r",
                               "tool": "webapp.xss", "references": [], "id": "F-1", "timestamp": "",
                               "tool_version": "", "raw": {}, "verification_status": "",
                               "verification_detail": "", "business_impact": "", "mitre_techniques": [],
                               "kind": "", "chain_assets": []}],
                "summary": "", "error": "", "metadata": {},
            }

        def fake_empty(target, **kwargs):
            return {"tool": "x", "target": target, "status": "no_findings", "findings": [],
                    "summary": "", "error": "", "metadata": {}}

        orig_get = tool_registry.get

        def fake_get(name):
            if name == "webapp.xss":
                return fake_xss
            if name in ("webapp.sqli", "webapp.ssrf"):
                return fake_empty
            return orig_get(name)

        monkeypatch.setattr(tool_registry, "get", fake_get)
        result = dast.run("http://example.com")

        assert result["status"] == "completed"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["tool"] == "appsec.dast"
        assert result["metadata"]["sub_tool_results"]["webapp.xss"]["status"] == "completed"

    def test_honest_degrade_on_local_path_target(self, tmp_path):
        result = dast.run(str(tmp_path))
        assert result["status"] == "out_of_scope"


class TestThreatModeling:
    """Real reuse of MitreMappingAgent / AttackChainAgent logic."""

    def test_honest_degrade_without_findings(self):
        result = threat_modeling.run("engagement-1")
        assert result["status"] == "no_findings"
        assert result["findings"] == []

    def test_real_technique_tagging_with_supplied_findings(self):
        findings = [
            {"title": "SQL injection in login form", "severity": "high", "confidence": "high",
             "affected_asset": "app.example.com", "tool": "webapp.sqli", "evidence": "", "remediation": ""},
        ]
        result = threat_modeling.run("engagement-1", findings=findings)
        assert result["status"] == "completed"
        assert result["metadata"]["technique_coverage"]
        assert "T1190" in result["metadata"]["technique_coverage"]

    def test_real_chain_detection_across_two_assets(self):
        findings = [
            {"title": "Leaked admin credential", "severity": "critical", "confidence": "high",
             "affected_asset": "host-a", "tool": "network.port_scan", "evidence": "", "remediation": ""},
            {"title": "Open port on internal service", "severity": "medium", "confidence": "high",
             "affected_asset": "host-b", "tool": "network.port_scan", "evidence": "", "remediation": ""},
        ]
        result = threat_modeling.run("engagement-1", findings=findings)
        assert result["status"] == "completed"
        assert result["metadata"]["chain_count"] >= 1
        assert any(f["kind"] == "synthetic_chain" for f in result["findings"])


# ═════════════════════════════════════════════════════════════════════════
# automation.* — real self-checks of this platform's own execution environment
# ═════════════════════════════════════════════════════════════════════════

class TestAutomationSelfChecks:
    def test_bash_automation_reports_real_local_capability(self):
        result = bash_automation.run("irrelevant-target")
        assert result["status"] == "completed"
        assert isinstance(result["metadata"]["confirmed_executable"], bool)
        # bash is genuinely present in this dev/CI environment (Git Bash on PATH)
        assert result["metadata"]["bash_path"] is not None
        assert result["metadata"]["confirmed_executable"] is True

    def test_powershell_automation_reports_real_local_capability(self):
        result = powershell_automation.run("irrelevant-target")
        assert result["status"] == "completed"
        assert isinstance(result["metadata"]["confirmed_executable"], bool)

    def test_python_scripting_reports_real_interpreter_and_modules(self):
        result = python_scripting.run("irrelevant-target")
        assert result["status"] == "completed"
        assert result["metadata"]["python_version"]
        # requests/ldap3 are real declared dependencies of this project
        assert result["metadata"]["modules_available"]["requests"] is True
        assert result["metadata"]["modules_available"]["ldap3"] is True

    @pytest.mark.parametrize("module", [security_orchestration, soar_playbooks])
    def test_orchestration_tools_do_real_registry_introspection(self, module):
        from nexus.tools.registry import tool_registry

        result = module.run("some-third-party-soar")
        assert result["status"] == "completed"
        assert result["metadata"]["total_tools"] == tool_registry.count
        assert result["metadata"]["total_tools"] >= 200
        assert result["metadata"]["meets_200_threshold"] is True

    @pytest.mark.parametrize("module", [ai_agent_development, custom_tool_development])
    def test_meta_capability_tools_honestly_explain_not_scan_shaped(self, module):
        result = module.run("irrelevant-target")
        assert result["status"] == "completed"
        assert result["metadata"]["scan_shaped"] is False

    @pytest.mark.parametrize("module", [
        ai_agent_development, bash_automation, custom_tool_development,
        powershell_automation, python_scripting, security_orchestration, soar_playbooks,
    ])
    def test_does_not_read_a_local_file_even_when_target_is_a_real_path(self, module, tmp_path):
        # Regression guard: these tools must never treat `target` as a local
        # path to read, matching test_automation_tools.py's existing contract.
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("top-secret-content-should-never-appear-in-findings", encoding="utf-8")
        result = module.run(target=str(secret_file))
        assert result["status"] == "completed"
        joined = json.dumps(result["findings"])
        assert "top-secret-content" not in joined


# ═════════════════════════════════════════════════════════════════════════
# iam.* — real LDAP / SAML / OIDC protocol checks
# ═════════════════════════════════════════════════════════════════════════

class TestLdapTesting:
    def test_unavailable_when_ldap3_not_installed(self):
        with patch.dict("sys.modules", {"ldap3": None}):
            result = ldap_testing.run("dc01.example.com")
        assert result["status"] == "unavailable"

    def test_flags_anonymous_bind_and_missing_starttls(self):
        fake_connection = MagicMock()
        fake_connection.bind.return_value = True
        fake_connection.open.return_value = None
        fake_connection.start_tls.return_value = False

        with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection):
            result = ldap_testing.run("dc01.example.com")

        assert result["status"] == "completed"
        titles = " ".join(f["title"] for f in result["findings"])
        assert "Anonymous LDAP bind allowed" in titles
        assert "StartTLS" in titles
        assert result["metadata"]["anonymous_bind_allowed"] is True
        assert result["metadata"]["starttls_supported"] is False

    def test_no_findings_when_hardened(self):
        fake_connection = MagicMock()
        fake_connection.bind.return_value = False
        fake_connection.open.return_value = None
        fake_connection.start_tls.return_value = True

        with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection):
            result = ldap_testing.run("dc01.example.com")

        assert result["status"] == "no_findings"
        assert result["findings"] == []

    def test_unavailable_on_connection_failure(self):
        with patch("ldap3.Server", side_effect=OSError("connection refused")):
            result = ldap_testing.run("not-a-dc.example.com")
        assert result["status"] == "unavailable"


class TestAdIam:
    def test_unavailable_when_ldap3_not_installed(self):
        with patch.dict("sys.modules", {"ldap3": None}):
            result = ad_iam.run("dc01.example.com")
        assert result["status"] == "unavailable"

    def test_flags_readable_root_dse_and_merges_kerberoast(self):
        fake_connection = MagicMock()
        fake_connection.bind.return_value = True
        fake_server_info = MagicMock()
        fake_server_info.other = {}
        fake_server_info.defaultNamingContext = "DC=example,DC=com"
        fake_server_info.domainFunctionality = None
        fake_server_info.forestFunctionality = None
        fake_server_info.supportedLDAPVersion = None
        fake_server_info.dnsHostName = None
        fake_connection.server.info = fake_server_info

        fake_kerberoast_result = {
            "status": "completed", "findings": [{
                "id": "F-1", "title": "Service Principal Name (SPN) Identified", "severity": "medium",
                "confidence": "certain", "affected_asset": "dc01.example.com", "evidence": "e",
                "remediation": "r", "tool": "active_directory.kerberoast", "references": [],
                "timestamp": "", "tool_version": "", "raw": {}, "verification_status": "",
                "verification_detail": "", "business_impact": "", "mitre_techniques": [],
                "kind": "", "chain_assets": [],
            }],
        }

        with patch("ldap3.Server"), patch("ldap3.Connection", return_value=fake_connection), \
             patch("nexus.tools.registry.tool_registry.get", return_value=lambda target, **kw: fake_kerberoast_result):
            result = ad_iam.run("dc01.example.com")

        assert result["status"] == "completed"
        titles = [f["title"] for f in result["findings"]]
        assert any("root DSE" in t for t in titles)
        assert any("SPN" in t for t in titles)
        assert all(f["tool"] == "iam.ad_iam" for f in result["findings"])


def _run_local_http_server(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class TestOidcDiscoveryTools:
    """Real HTTP GETs against a genuine local test server."""

    @pytest.mark.parametrize("module", [oauth_testing, sso_testing])
    def test_flags_missing_pkce_and_implicit_flow(self, module):
        doc = {
            "issuer": "https://idp.example.com",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "code_challenge_methods_supported": ["plain"],
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    body = json.dumps(doc).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *a):
                pass

        server, thread = _run_local_http_server(Handler)
        try:
            result = module.run(f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()

        assert result["status"] == "completed"
        titles = " ".join(f["title"] for f in result["findings"])
        assert "PKCE" in titles
        assert "implicit" in titles.lower()

    @pytest.mark.parametrize("module", [oauth_testing, sso_testing])
    def test_no_findings_when_no_discovery_endpoint(self, module):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.end_headers()

            def log_message(self, *a):
                pass

        server, thread = _run_local_http_server(Handler)
        try:
            result = module.run(f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()

        assert result["status"] == "no_findings"
        assert result["findings"] == []


class TestSamlTesting:
    """Real HTTP GET + regex extraction against a genuine local test server."""

    def test_flags_unsigned_metadata(self):
        metadata = '<EntityDescriptor entityID="https://sp.example.com"><SPSSODescriptor></SPSSODescriptor></EntityDescriptor>'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/saml/metadata":
                    body = metadata.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/xml")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *a):
                pass

        server, thread = _run_local_http_server(Handler)
        try:
            result = saml_testing.run(f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()

        assert result["status"] == "completed"
        titles = " ".join(f["title"] for f in result["findings"])
        assert "no embedded signing certificate" in titles

    def test_no_findings_when_no_saml_metadata(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.end_headers()

            def log_message(self, *a):
                pass

        server, thread = _run_local_http_server(Handler)
        try:
            result = saml_testing.run(f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()

        assert result["status"] == "no_findings"


class TestMfaAndPamHonestDegrade:
    def test_mfa_reviews_requires_credentials_without_data(self):
        result = mfa_reviews.run("tenant.example.com")
        assert result["status"] == "requires_credentials"
        assert result["findings"] == []

    def test_mfa_reviews_real_analysis_with_supplied_data(self):
        data = [
            {"user": "alice", "methods": []},
            {"user": "bob", "methods": ["sms"]},
            {"user": "carol", "methods": ["totp"]},
        ]
        result = mfa_reviews.run("tenant.example.com", mfa_enrollment_data=data)
        assert result["status"] == "completed"
        assert result["metadata"]["no_mfa_count"] == 1
        assert result["metadata"]["weak_only_count"] == 1

    def test_pam_testing_requires_credentials_without_data(self):
        result = pam_testing.run("vault.example.com")
        assert result["status"] == "requires_credentials"
        assert result["findings"] == []

    def test_pam_testing_real_analysis_with_supplied_data(self):
        data = [
            {"account": "svc_backup", "shared": True, "checkout_required": False,
             "session_recording": False, "last_rotated_days": 200},
            {"account": "svc_ok", "shared": False, "checkout_required": True,
             "session_recording": True, "last_rotated_days": 10},
        ]
        result = pam_testing.run("vault.example.com", pam_account_data=data)
        assert result["status"] == "completed"
        assert result["metadata"]["shared_unchecked_count"] == 1
        assert result["metadata"]["unrecorded_count"] == 1
        assert result["metadata"]["stale_rotation_count"] == 1
