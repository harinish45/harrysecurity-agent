"""Unit tests for nexus.advanced.threat_radar.

Per this repo's pytest config ("The test suite is self-contained and never
contacts the public internet"), no test in this file makes a real network
call. NVD/CISA responses are supplied as canned fixture JSON via monkeypatch
on ``requests.get``, and the failure paths are exercised by making the
patched ``requests.get`` raise, asserting graceful (empty-list) degradation
rather than a crash.
"""
from __future__ import annotations

import requests

from nexus.advanced.threat_radar import ThreatRadar, cvss_score_to_severity


# -- severity mapping ------------------------------------------------------

def test_cvss_score_to_severity_thresholds():
    assert cvss_score_to_severity(9.8) == "critical"
    assert cvss_score_to_severity(9.0) == "critical"
    assert cvss_score_to_severity(8.9) == "high"
    assert cvss_score_to_severity(7.0) == "high"
    assert cvss_score_to_severity(6.9) == "medium"
    assert cvss_score_to_severity(4.0) == "medium"
    assert cvss_score_to_severity(3.9) == "low"
    assert cvss_score_to_severity(0.1) == "low"
    assert cvss_score_to_severity(0.0) == "info"
    assert cvss_score_to_severity(None) == "info"


# -- NVD check_software: graceful failure -----------------------------------

def test_check_software_network_failure_returns_empty(monkeypatch):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError("no network in sandbox")

    monkeypatch.setattr(requests, "get", fake_get)

    radar = ThreatRadar()
    result = radar.check_software("openssh", "8.0")
    assert result == []


def test_check_software_empty_name_returns_empty_without_network_call(monkeypatch):
    called = {"n": 0}

    def fake_get(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("should not be called for empty software name")

    monkeypatch.setattr(requests, "get", fake_get)

    radar = ThreatRadar()
    assert radar.check_software("") == []
    assert called["n"] == 0


# -- NVD check_software: canned fixture parsing ------------------------------

_NVD_FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-99999",
                "descriptions": [
                    {"lang": "en", "value": "A critical remote code execution flaw."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8}}
                    ]
                },
                "references": [
                    {"url": "https://example.com/advisory"},
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2022-11111",
                "descriptions": [
                    {"lang": "en", "value": "A minor information disclosure issue."}
                ],
                "metrics": {},
                "references": [],
            }
        },
    ]
}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_check_software_parses_fixture_into_findings(monkeypatch):
    def fake_get(url, params=None, timeout=None, headers=None):
        assert "keywordSearch" in params
        return _FakeResponse(_NVD_FIXTURE)

    monkeypatch.setattr(requests, "get", fake_get)

    radar = ThreatRadar()
    findings = radar.check_software("some-software", "1.0")

    assert len(findings) == 2
    high = next(f for f in findings if "CVE-2023-99999" in f["title"])
    assert high["severity"] == "critical"
    assert high["affected_asset"] == "some-software"
    assert "https://example.com/advisory" in high["references"]

    low_info = next(f for f in findings if "CVE-2022-11111" in f["title"])
    assert low_info["severity"] == "info"  # no CVSS score present


# -- CISA KEV: graceful failure ----------------------------------------------

def test_check_kev_network_failure_returns_empty(monkeypatch):
    def fake_get(*args, **kwargs):
        raise requests.exceptions.Timeout("no network in sandbox")

    monkeypatch.setattr(requests, "get", fake_get)

    radar = ThreatRadar()
    result = radar.check_kev(["CVE-2021-44228"])
    assert result == []


def test_check_kev_empty_ids_returns_empty_without_network_call(monkeypatch):
    called = {"n": 0}

    def fake_get(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("should not be called for empty cve_ids")

    monkeypatch.setattr(requests, "get", fake_get)

    radar = ThreatRadar()
    assert radar.check_kev([]) == []
    assert called["n"] == 0


# -- CISA KEV: canned fixture matching + caching -----------------------------

_KEV_FIXTURE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vulnerabilityName": "Apache Log4j RCE",
            "vendorProject": "Apache",
            "product": "Log4j",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "shortDescription": "Remote code execution via JNDI lookup.",
            "requiredAction": "Apply updates per vendor instructions.",
        },
        {
            "cveID": "CVE-2020-00000",
            "vulnerabilityName": "Unrelated Vuln",
            "vendorProject": "Foo",
            "product": "Bar",
            "dateAdded": "2020-01-01",
            "dueDate": "",
            "shortDescription": "Not queried in this test.",
            "requiredAction": "",
        },
    ]
}


def test_check_kev_matches_and_marks_critical(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return _FakeResponse(_KEV_FIXTURE)

    monkeypatch.setattr(requests, "get", fake_get)

    radar = ThreatRadar()
    result = radar.check_kev(["CVE-2021-44228", "CVE-9999-00000"])

    assert len(result) == 1
    finding = result[0]
    assert finding["severity"] == "critical"
    assert finding["confidence"] == "certain"
    assert "2021-12-10" in finding["evidence"]
    assert calls["n"] == 1


def test_check_kev_uses_in_memory_cache_within_ttl(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return _FakeResponse(_KEV_FIXTURE)

    monkeypatch.setattr(requests, "get", fake_get)

    radar = ThreatRadar()
    radar.check_kev(["CVE-2021-44228"])
    radar.check_kev(["CVE-2020-00000"])

    # Both calls hit the same cached catalog fetch -- only one HTTP call.
    assert calls["n"] == 1
