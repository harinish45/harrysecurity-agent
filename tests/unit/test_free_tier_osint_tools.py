"""Making nexus-strike runnable free-tier-only: several recon/threat-intel
tools previously honestly degraded to STATUS_REQUIRES_CREDENTIALS whenever
no PAID API key was configured (Shodan, Censys) even though genuinely free
alternatives exist. Fixed:

- reconnaissance.shodan_search: now defaults to Shodan's free, unauthenticated
  InternetDB endpoint (https://internetdb.shodan.io/<ip>) instead of requiring
  a paid Search API key; the paid API is used only as an optional enhancement
  when SHODAN_API_KEY is actually set.
- reconnaissance.censys_search: migrated from the defunct legacy
  search.censys.io/api/v2 Basic-Auth endpoint (no longer serves free
  accounts) to the current Censys Platform API, and its messaging now
  clarifies the required Personal Access Token is FREE to create (100
  lookups/month, no payment method) rather than implying a paid subscription.
- threat_intel.{ioc_enrichment,threat_feeds}: messaging clarified that
  VirusTotal/OTX API keys are free to obtain, not paid — logic was already
  correct, this was a wording-only fix.

Confirmed NOT changed (genuinely infra-gated, no free-tier equivalent
exists): active_directory/* (needs the target's own AD credentials),
cloud/{aws,azure,gcp}_review.py + iam_audit.py (needs the user's own cloud
account credentials), blue_team/{endpoint_protection,edr_analysis}.py
(needs local endpoint-agent/EDR-platform access).
"""
from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from nexus.tools.reconnaissance import censys_search, shodan_search
from nexus.tools.threat_intel import ioc_enrichment, threat_feeds


# ── shodan_search.py — free InternetDB path ─────────────────────────────

def _fake_urlopen_json(payload: dict, status: int = 200):
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).decode() if isinstance(payload, bytes) else json.dumps(payload).encode()
    resp.status = status
    resp.__enter__ = lambda self: resp
    resp.__exit__ = lambda *a: False
    return resp


def test_shodan_uses_free_internetdb_by_default(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    payload = {"ip": "1.2.3.4", "ports": [22, 80], "hostnames": ["example.com"], "cpes": [], "vulns": ["CVE-2020-1234"]}

    def fake_safe_urlopen(req, timeout=None, context=None):
        assert "internetdb.shodan.io" in req.full_url
        return _fake_urlopen_json(payload)

    with patch("nexus.tools.reconnaissance.shodan_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", side_effect=fake_safe_urlopen):
        result = shodan_search.run("example.com")

    assert result["status"] == "completed"
    assert result["metadata"]["source"] == "internetdb_free"
    assert any("CVE-2020-1234" in f["evidence"] for f in result["findings"])


def test_shodan_internetdb_no_data_is_honest_no_findings(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    def fake_safe_urlopen(req, timeout=None, context=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", None, None)

    with patch("nexus.tools.reconnaissance.shodan_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", side_effect=fake_safe_urlopen):
        result = shodan_search.run("noindex.example.com")

    assert result["status"] == "no_findings"


def test_shodan_uses_paid_api_when_key_present(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fake-paid-key")
    payload = {"ports": [443], "data": [{"port": 443, "product": "nginx", "data": "HTTP/1.1"}], "vulns": []}

    def fake_safe_urlopen(req, timeout=None, context=None):
        assert "api.shodan.io" in req.full_url
        return _fake_urlopen_json(payload)

    with patch("nexus.tools.reconnaissance.shodan_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", side_effect=fake_safe_urlopen):
        result = shodan_search.run("example.com")

    assert result["status"] == "completed"
    assert result["metadata"]["source"] == "full_api"


def test_shodan_bad_paid_key_falls_back_to_free_path(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "bad-key")
    call_urls = []

    def fake_safe_urlopen(req, timeout=None, context=None):
        call_urls.append(req.full_url)
        if "api.shodan.io" in req.full_url:
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, None)
        return _fake_urlopen_json({"ip": "1.2.3.4", "ports": [80], "hostnames": [], "cpes": [], "vulns": []})

    with patch("nexus.tools.reconnaissance.shodan_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", side_effect=fake_safe_urlopen):
        result = shodan_search.run("example.com")

    assert result["status"] == "completed"
    assert any("internetdb.shodan.io" in u for u in call_urls)


# ── censys_search.py — free-token messaging + current Platform API ──────

def test_censys_requires_credentials_message_says_free():
    result = censys_search.run("example.com", censys_pat=None)
    assert result["status"] == "requires_credentials"
    assert "FREE" in result["summary"]
    assert "payment" in result["summary"].lower()


def test_censys_uses_platform_api_endpoint_when_token_present(monkeypatch):
    payload = {"result": {"services": [{"port": 443, "service_name": "HTTPS", "software": []}]}}

    def fake_safe_urlopen(req, timeout=None, context=None):
        assert "api.platform.censys.io" in req.full_url
        assert req.get_header("Authorization") == "Bearer free-token-123"
        return _fake_urlopen_json(payload)

    with patch("nexus.tools.reconnaissance.censys_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.censys_search.safe_urlopen", side_effect=fake_safe_urlopen):
        result = censys_search.run("example.com", censys_pat="free-token-123")

    assert result["status"] == "completed"
    assert len(result["findings"]) == 1


def test_censys_rate_limit_is_honest_not_crash(monkeypatch):
    def fake_safe_urlopen(req, timeout=None, context=None):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", None, None)

    with patch("nexus.tools.reconnaissance.censys_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.censys_search.safe_urlopen", side_effect=fake_safe_urlopen):
        result = censys_search.run("example.com", censys_pat="free-token-123")

    assert result["status"] == "unavailable"
    assert "credit" in result["summary"].lower() or "limit" in result["summary"].lower()


# ── threat_intel messaging clarity ───────────────────────────────────────

def test_ioc_enrichment_no_key_message_says_free(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    result = ioc_enrichment.run("example.com")
    assert result["status"] == "requires_credentials"
    assert "FREE" in result["summary"]


def test_threat_feeds_no_key_message_says_free(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    result = threat_feeds.run("example.com")
    assert result["status"] == "requires_credentials"
    assert "FREE" in result["summary"]


def test_threat_feeds_ip_path_is_still_free_no_key(monkeypatch):
    """The IP path (Spamhaus ZEN DNSBL) never needed a key and must still not need one."""
    import socket as socket_mod
    with patch("nexus.tools.threat_intel._common.socket.gethostbyname", side_effect=socket_mod.gaierror("NXDOMAIN")):
        result = threat_feeds.run("203.0.113.1")
    assert result["status"] == "no_findings"
