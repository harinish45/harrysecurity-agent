"""All 16 threat_intel/vuln_assessment tools (8 + 8) used to share
byte-for-byte identical fake logic (a DNS resolve + a bare HTTP GET on
`/`, unrelated to what each tool claimed to do) — caught during this
session's audit. These tests prove each tool now has real, tool-specific
logic: real external-API parsing (NVD, CISA KEV, Spamhaus DNSBL — all
mocked here, never hitting the real services), a real CVSS 3.1 base-score
formula verified against a known reference vector, and honest,
tool-specific degrade paths when the data a real check needs isn't
available.
"""
from __future__ import annotations

import json
import socket as socket_module
import urllib.error
from unittest.mock import patch

from nexus.tools.registry import tool_registry
from nexus.tools.threat_intel import (
    attck_mapping,
    campaign_analysis,
    dark_web_monitoring,
    ioc_enrichment,
    malware_family_tracking,
    threat_actor_profiling,
    threat_feeds,
    ti_ioc_collection,
)
from nexus.tools.vuln_assessment import (
    cve_analysis,
    network_vuln_scanning,
    patch_verification,
    prioritization,
    remediation_validation,
    reporting_vuln,
    risk_scoring,
    web_vuln_scanning,
)


class _FakeResponse:
    """Minimal stand-in for the object `safe_urlopen()` returns, used as a
    context manager exactly like the real urllib response object."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def read(self, *_a, **_kw):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _json_response(obj, status: int = 200) -> _FakeResponse:
    return _FakeResponse(json.dumps(obj).encode("utf-8"), status=status)


# ═══════════════════════════════════════════════════════════════════════
# risk_scoring — real CVSS v3.1 base-score formula
# ═══════════════════════════════════════════════════════════════════════

def test_cvss31_known_reference_vector_scores_9_8():
    """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is the textbook CVSS 3.1
    reference vector with a published base score of 9.8 — this checks our
    formula implementation against that known-correct value."""
    result = risk_scoring.cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result["base_score"] == 9.8
    assert result["severity"] == "critical"


def test_cvss31_low_severity_vector():
    result = risk_scoring.cvss31_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert 0.0 < result["base_score"] < 4.0
    assert result["severity"] == "low"


def test_cvss31_scope_changed_vector_stays_in_bounds():
    result = risk_scoring.cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H")
    assert 0.0 <= result["base_score"] <= 10.0
    assert result["severity"] == "critical"


def test_cvss31_invalid_vector_raises():
    import pytest
    with pytest.raises(ValueError):
        risk_scoring.cvss31_base_score("CVSS:3.1/AV:N/AC:L")  # missing required base metrics


def test_risk_scoring_run_computes_real_score_from_vector():
    out = risk_scoring.run("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert out["status"] == "completed"
    assert out["metadata"]["base_score"] == 9.8
    assert out["findings"][0]["severity"] == "critical"


def test_risk_scoring_honest_degrade_without_vector():
    out = risk_scoring.run("example.com")
    assert out["status"] == "out_of_scope"
    assert "vector" in out["error"].lower()


def test_risk_scoring_bad_vector_fails_honestly_not_fake_success():
    out = risk_scoring.run("CVSS:3.1/AV:N/AC:L")
    assert out["status"] == "failed"
    assert "missing" in out["error"].lower()


# ═══════════════════════════════════════════════════════════════════════
# cve_analysis — real NVD CVE API parsing
# ═══════════════════════════════════════════════════════════════════════

_NVD_SAMPLE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"}],
                "metrics": {"cvssMetricV31": [{"baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.8}}]},
                "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}],
            }
        }
    ],
}


def test_cve_analysis_parses_real_nvd_response():
    with patch("nexus.tools.vuln_assessment.cve_analysis.safe_urlopen", return_value=_json_response(_NVD_SAMPLE)):
        out = cve_analysis.run("Apache 2.4.49")
    assert out["status"] == "completed"
    assert len(out["findings"]) == 1
    assert "CVE-2021-41773" in out["findings"][0]["title"]
    assert out["findings"][0]["severity"] == "critical"


def test_cve_analysis_zero_results_is_honest_no_findings():
    with patch("nexus.tools.vuln_assessment.cve_analysis.safe_urlopen",
               return_value=_json_response({"vulnerabilities": []})):
        out = cve_analysis.run("SomeObscureProductNameXyz")
    assert out["status"] == "no_findings"


def test_cve_analysis_rate_limited_is_honest_not_fake_success():
    err = urllib.error.HTTPError("url", 429, "Too Many Requests", {}, None)
    with patch("nexus.tools.vuln_assessment.cve_analysis.safe_urlopen", side_effect=err):
        out = cve_analysis.run("nginx 1.18")
    assert out["status"] == "unavailable"
    assert "429" in out["error"]


def test_cve_analysis_host_target_is_out_of_scope():
    out = cve_analysis.run("192.168.1.1")
    assert out["status"] == "out_of_scope"


def test_cve_analysis_url_target_is_out_of_scope():
    out = cve_analysis.run("https://example.com/path")
    assert out["status"] == "out_of_scope"


# ═══════════════════════════════════════════════════════════════════════
# prioritization — real CISA KEV feed
# ═══════════════════════════════════════════════════════════════════════

_KEV_SAMPLE = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "shortDescription": "Log4Shell RCE",
         "requiredAction": "Patch to 2.17.0+"}
    ]
}


def test_prioritization_kev_listed_cve_is_immediate():
    with patch("nexus.tools.vuln_assessment.prioritization.safe_urlopen", return_value=_json_response(_KEV_SAMPLE)):
        out = prioritization.run("CVE-2021-44228")
    assert out["status"] == "completed"
    assert out["metadata"]["kev_listed"] is True
    assert out["findings"][0]["severity"] == "critical"


def test_prioritization_non_kev_cve_uses_severity_hint():
    with patch("nexus.tools.vuln_assessment.prioritization.safe_urlopen", return_value=_json_response(_KEV_SAMPLE)):
        out = prioritization.run("CVE-2099-99999", severity="medium")
    assert out["status"] == "completed"
    assert out["metadata"]["kev_listed"] is False
    assert out["findings"][0]["severity"] == "medium"


def test_prioritization_without_cve_id_is_honest_degrade():
    out = prioritization.run("some-label-without-a-cve")
    assert out["status"] == "out_of_scope"
    assert "CVE" in out["error"]


def test_prioritization_rate_limited_is_honest():
    err = urllib.error.HTTPError("url", 403, "Forbidden", {}, None)
    with patch("nexus.tools.vuln_assessment.prioritization.safe_urlopen", side_effect=err):
        out = prioritization.run("CVE-2021-44228")
    assert out["status"] == "unavailable"


# ═══════════════════════════════════════════════════════════════════════
# threat_feeds / ioc_enrichment / ti_ioc_collection — real DNSBL + keyed feeds
# ═══════════════════════════════════════════════════════════════════════

def test_threat_feeds_ip_listed_on_dnsbl():
    with patch("nexus.tools.threat_intel._common.socket.gethostbyname", return_value="127.0.0.2"):
        out = threat_feeds.run("1.2.3.4")
    assert out["status"] == "completed"
    assert out["findings"][0]["severity"] == "high"
    assert out["metadata"]["dnsbl"]["listed"] is True


def test_threat_feeds_ip_clean_on_dnsbl():
    with patch("nexus.tools.threat_intel._common.socket.gethostbyname", side_effect=socket_module.gaierror()):
        out = threat_feeds.run("8.8.8.8")
    assert out["status"] == "no_findings"
    assert out["metadata"]["dnsbl"]["listed"] is False


def test_threat_feeds_domain_without_api_key_is_honest_degrade(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    out = threat_feeds.run("example.com")
    assert out["status"] == "requires_credentials"
    assert "VIRUSTOTAL_API_KEY" in out["error"]


def test_threat_feeds_domain_with_vt_key_makes_real_call(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key-123")
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with patch("nexus.tools.threat_intel._common.safe_urlopen",
               return_value=_json_response({"data": {"id": "example.com"}})):
        out = threat_feeds.run("example.com")
    assert out["status"] == "completed"
    assert out["metadata"]["source"] == "VirusTotal"


def test_ioc_enrichment_ip_adds_reverse_dns_context():
    with patch("nexus.tools.threat_intel._common.socket.gethostbyname", side_effect=socket_module.gaierror()), \
         patch("nexus.tools.threat_intel.ioc_enrichment.socket.gethostbyaddr",
               return_value=("dns.google", [], ["8.8.8.8"])):
        out = ioc_enrichment.run("8.8.8.8")
    assert out["status"] == "completed"
    assert "dns.google" in out["findings"][0]["evidence"]


def test_ioc_enrichment_domain_without_key_is_honest_degrade(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    out = ioc_enrichment.run("evil.example.com")
    assert out["status"] == "requires_credentials"


def test_ti_ioc_collection_domain_without_key_still_records_honestly(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    out = ti_ioc_collection.run("evil.example.com")
    assert out["status"] == "completed"
    assert out["metadata"]["record"]["verdict"] == "unenriched"
    assert out["metadata"]["record"]["type"] == "domain"


def test_ti_ioc_collection_classifies_hash_type():
    out = ti_ioc_collection.run("d41d8cd98f00b204e9800998ecf8427e")  # MD5-shaped
    # No key configured -> unenriched, but classification itself is real
    assert out["metadata"]["record"]["type"] == "hash"


# ═══════════════════════════════════════════════════════════════════════
# attck_mapping — real reuse of mitre_mapping_agent's technique table
# ═══════════════════════════════════════════════════════════════════════

def test_attck_mapping_maps_finding_list_to_real_techniques():
    findings_in = [{"title": "SQL injection in login form", "tool": "webapp.sqli"}]
    out = attck_mapping.run("example.com", findings=findings_in)
    assert out["status"] == "completed"
    annotated = out["metadata"]["annotated_findings"]
    assert annotated[0]["mitre_techniques"][0]["id"] == "T1190"


def test_attck_mapping_falls_back_to_target_text():
    out = attck_mapping.run("port scan results")
    assert out["status"] == "completed"
    assert "T1046" in out["metadata"]["technique_coverage"]


def test_attck_mapping_no_keyword_match_is_honest_no_findings():
    out = attck_mapping.run("zzz_no_keyword_match_here_zzz")
    assert out["status"] == "no_findings"


def test_attck_mapping_shares_table_with_mitre_mapping_agent():
    from nexus.agents.orchestrator.mitre_mapping_agent import _TECHNIQUE_TABLE
    assert attck_mapping._TECHNIQUE_TABLE is _TECHNIQUE_TABLE


# ═══════════════════════════════════════════════════════════════════════
# campaign_analysis / malware_family_tracking / threat_actor_profiling —
# genuinely specific honest degrades + real logic when given case data
# ═══════════════════════════════════════════════════════════════════════

def test_campaign_analysis_requires_2plus_iocs():
    out = campaign_analysis.run("case-1", iocs=["only-one.example.com"])
    assert out["status"] == "unavailable"
    assert "requires_case_data" in out["error"]


def test_campaign_analysis_correlates_shared_infrastructure():
    def fake_resolve(host):
        return "1.2.3.4" if host in ("a.example.com", "b.example.com") else None
    with patch("nexus.tools.threat_intel.campaign_analysis._resolve", side_effect=fake_resolve):
        out = campaign_analysis.run("case-1", iocs=["a.example.com", "b.example.com", "c.other.com"])
    assert out["status"] == "completed"
    assert len(out["findings"]) == 1
    assert "1.2.3.4" in out["metadata"]["clusters"]


def test_campaign_analysis_no_shared_infra_is_honest_no_findings():
    with patch("nexus.tools.threat_intel.campaign_analysis._resolve", return_value=None):
        out = campaign_analysis.run("case-1", iocs=["a.example.com", "b.example.com"])
    assert out["status"] == "no_findings"


def test_malware_family_tracking_requires_sample_corpus():
    out = malware_family_tracking.run("case-1")
    assert out["status"] == "unavailable"
    assert "requires_case_data" in out["error"]


def test_malware_family_tracking_clusters_by_yara_rule():
    hits = [
        {"sha256": "a" * 64, "rule": "FamilyX_dropper"},
        {"sha256": "b" * 64, "rule": "FamilyX_dropper"},
        {"sha256": "c" * 64, "rule": "FamilyY_backdoor"},
    ]
    out = malware_family_tracking.run("case-1", yara_hits=hits)
    assert out["status"] == "completed"
    assert out["metadata"]["families"]["FamilyX_dropper"] == 2
    assert out["metadata"]["families"]["FamilyY_backdoor"] == 1


def test_threat_actor_profiling_requires_ttp_history():
    out = threat_actor_profiling.run("case-1", ttp_history=[{"technique_id": "T1190"}])
    assert out["status"] == "unavailable"
    assert "requires_case_data" in out["error"]


def test_threat_actor_profiling_aggregates_real_frequency():
    history = [{"technique_id": "T1190"}, {"technique_id": "T1190"}, {"technique_id": "T1110"}]
    out = threat_actor_profiling.run("case-1", ttp_history=history)
    assert out["status"] == "completed"
    assert out["metadata"]["technique_frequency"]["T1190"] == 2
    # Never fabricates an actor name/attribution
    assert not any("actor" in f["title"].lower() and "unknown" not in f["title"].lower()
                   for f in out["findings"])


def test_dark_web_monitoring_always_honestly_out_of_scope():
    out = dark_web_monitoring.run("anything")
    assert out["status"] == "out_of_scope"
    assert "tor" in out["error"].lower()


# ═══════════════════════════════════════════════════════════════════════
# network_vuln_scanning / web_vuln_scanning — real aggregation via
# tool_registry.run
# ═══════════════════════════════════════════════════════════════════════

def test_network_vuln_scanning_merges_real_component_findings():
    def fake_run(name, target, **_kw):
        if name == "network.port_scan":
            return {"status": "completed",
                     "findings": [{"title": "Open port 22", "severity": "medium", "tool": "network.port_scan"}],
                     "summary": "1 open port"}
        return {"status": "no_findings", "findings": [], "summary": "nothing"}

    with patch.object(tool_registry, "run", side_effect=fake_run):
        out = network_vuln_scanning.run("10.0.0.5")
    assert out["status"] == "completed"
    assert len(out["findings"]) == 1
    assert out["metadata"]["component_tools"]["network.port_scan"]["status"] == "completed"
    assert out["metadata"]["component_tools"]["network.service_enum"]["status"] == "no_findings"


def test_network_vuln_scanning_all_failed_is_honest():
    def fake_run(name, target, **_kw):
        return {"status": "failed", "findings": [], "error": "boom", "summary": ""}

    with patch.object(tool_registry, "run", side_effect=fake_run):
        out = network_vuln_scanning.run("10.0.0.5")
    assert out["status"] == "failed"


def test_web_vuln_scanning_merges_real_component_findings():
    def fake_run(name, target, **_kw):
        if name == "cryptography.tls_testing":
            return {"status": "completed",
                     "findings": [{"title": "Weak TLS", "severity": "high", "tool": "cryptography.tls_testing"}],
                     "summary": "1 weak cipher"}
        return {"status": "no_findings", "findings": [], "summary": ""}

    with patch.object(tool_registry, "run", side_effect=fake_run):
        out = web_vuln_scanning.run("https://example.com")
    assert out["status"] == "completed"
    assert len(out["findings"]) == 1
    assert set(out["metadata"]["component_tools"]) == {"webapp.sqli", "webapp.xss", "cryptography.tls_testing"}


# ═══════════════════════════════════════════════════════════════════════
# patch_verification — real detection reuse + honest comparison gating
# ═══════════════════════════════════════════════════════════════════════

def test_patch_verification_no_banner_is_honest_no_findings():
    with patch.object(tool_registry, "run", return_value={"status": "no_findings", "findings": [], "summary": ""}):
        out = patch_verification.run("example.com")
    assert out["status"] == "no_findings"


def test_patch_verification_detected_without_reference_is_honest_degrade():
    banner_result = {
        "status": "completed",
        "findings": [{
            "evidence": "Port 22/SSH\nProduct: OpenSSH\nVersion: 8.2\nBanner: SSH-2.0-OpenSSH_8.2",
            "affected_asset": "example.com:22",
        }],
    }
    with patch.object(tool_registry, "run", return_value=banner_result):
        out = patch_verification.run("example.com")
    assert out["status"] == "unavailable"
    assert "expected_version" in out["error"]
    assert out["metadata"]["detected_versions"][0]["product"] == "OpenSSH"


def test_patch_verification_real_comparison_flags_outdated():
    banner_result = {
        "status": "completed",
        "findings": [{
            "evidence": "Port 22/SSH\nProduct: OpenSSH\nVersion: 8.2\nBanner: SSH-2.0-OpenSSH_8.2",
            "affected_asset": "example.com:22",
        }],
    }
    with patch.object(tool_registry, "run", return_value=banner_result):
        out = patch_verification.run("example.com", expected_version="9.8")
    assert out["status"] == "completed"
    assert out["findings"][0]["severity"] == "high"


def test_patch_verification_real_comparison_confirms_current():
    banner_result = {
        "status": "completed",
        "findings": [{
            "evidence": "Port 22/SSH\nProduct: OpenSSH\nVersion: 9.8\nBanner: SSH-2.0-OpenSSH_9.8",
            "affected_asset": "example.com:22",
        }],
    }
    with patch.object(tool_registry, "run", return_value=banner_result):
        out = patch_verification.run("example.com", expected_version="9.8")
    assert out["status"] == "completed"
    assert out["findings"][0]["severity"] == "info"


# ═══════════════════════════════════════════════════════════════════════
# remediation_validation — real re-run + verification_agent reuse
# ═══════════════════════════════════════════════════════════════════════

def test_remediation_validation_requires_finding_kwarg():
    out = remediation_validation.run("example.com")
    assert out["status"] == "unavailable"
    assert "requires_case_data" in out["error"]


def test_remediation_validation_confirms_remediated_when_finding_gone():
    def fake_run(name, target, **_kw):
        return {"status": "no_findings", "findings": [], "summary": "clean"}

    with patch.object(tool_registry, "run", side_effect=fake_run):
        out = remediation_validation.run(
            "example.com", finding={"tool": "network.port_scan", "title": "Open port 22"}
        )
    assert out["status"] == "no_findings"
    assert "remediated" in out["summary"].lower()


def test_remediation_validation_flags_finding_that_still_reproduces():
    def fake_run(name, target, **_kw):
        return {
            "status": "completed",
            "findings": [{
                "title": "Open port 22",
                "severity": "medium",
                "affected_asset": "example.com:22",
                "evidence": "TCP connect to example.com:22 succeeded",
            }],
            "summary": "1 finding",
        }

    with patch.object(tool_registry, "run", side_effect=fake_run), \
         patch("nexus.agents.orchestrator.verification_agent.VerificationAgent._verify_one",
               return_value=("non_replayable", "no replayable evidence")):
        out = remediation_validation.run(
            "example.com", finding={"tool": "network.port_scan", "title": "Open port 22"}
        )
    assert out["status"] == "completed"
    assert "NOT confirmed" in out["findings"][0]["title"]
    assert out["metadata"]["replay_verdict"] == "non_replayable"


def test_remediation_validation_unknown_tool_fails_honestly():
    out = remediation_validation.run(
        "example.com", finding={"tool": "not.a.real.tool", "title": "whatever"}
    )
    assert out["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════════
# reporting_vuln — real grouping/counting
# ═══════════════════════════════════════════════════════════════════════

def test_reporting_vuln_no_findings_is_honest():
    out = reporting_vuln.run("example.com")
    assert out["status"] == "no_findings"


def test_reporting_vuln_groups_by_severity_with_real_counts():
    findings = [
        {"title": "a", "severity": "critical", "tool": "x"},
        {"title": "b", "severity": "critical", "tool": "x"},
        {"title": "c", "severity": "low", "tool": "y"},
    ]
    out = reporting_vuln.run("example.com", findings=findings)
    assert out["status"] == "completed"
    assert out["metadata"]["severity_counts"]["critical"] == 2
    assert out["metadata"]["severity_counts"]["low"] == 1
    assert out["metadata"]["total_findings"] == 3
    assert out["metadata"]["findings_by_tool"]["x"] == 2
