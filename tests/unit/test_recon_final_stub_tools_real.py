"""github_recon.py, shodan_search.py, censys_search.py, email_harvest.py,
google_dorking.py, and social_osint.py in nexus/tools/reconnaissance were
6 of the last 13 genuine stub survivors identified by a follow-up audit
after this session's main stub-to-real conversion campaign — still the
old generic "DNS resolve + bare HTTP GET" template with stale registry
descriptions. Fixed here: real GitHub code-search API, real Shodan/Censys
API calls with honest requires_credentials degrade when no key is
supplied, real MX/SPF/DMARC DNS lookups, real generated Google dork
queries (never scrapes Google itself, which would violate its ToS), and
real ToS-friendly HTTP HEAD presence checks across common platforms.
"""
from __future__ import annotations

import json
import socket
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from nexus.tools.reconnaissance import (
    censys_search,
    email_harvest,
    github_recon,
    google_dorking,
    shodan_search,
    social_osint,
)


# ── github_recon.py ──────────────────────────────────────────────────────

def _fake_http_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    return resp


def test_github_recon_reports_real_matches():
    payload = {"total_count": 2, "items": [
        {"repository": {"full_name": "acme/infra"}, "path": "config.yml", "html_url": "https://github.com/acme/infra/blob/main/config.yml"},
    ]}
    with patch("nexus.tools.reconnaissance.github_recon.safe_urlopen", return_value=_fake_http_response(payload)):
        result = github_recon.run("example.com")
    assert result["status"] == "completed"
    assert result["metadata"]["total_count"] == 2
    assert "acme/infra" in result["findings"][0]["evidence"]


def test_github_recon_no_findings_on_empty_results():
    with patch("nexus.tools.reconnaissance.github_recon.safe_urlopen", return_value=_fake_http_response({"total_count": 0, "items": []})):
        result = github_recon.run("example.com")
    assert result["status"] == "no_findings"


def test_github_recon_honest_unavailable_on_rate_limit():
    err = HTTPError("url", 403, "rate limited", {}, None)
    with patch("nexus.tools.reconnaissance.github_recon.safe_urlopen", side_effect=err):
        result = github_recon.run("example.com")
    assert result["status"] == "unavailable"


# ── shodan_search.py ─────────────────────────────────────────────────────

def test_shodan_search_uses_free_internetdb_without_api_key(monkeypatch):
    # Later fixed to default to Shodan's free, unauthenticated InternetDB
    # endpoint instead of requiring a paid Search API key.
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    payload = {"ip": "1.2.3.4", "ports": [], "hostnames": [], "cpes": [], "vulns": []}
    with patch("socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", return_value=_fake_http_response(payload)):
        result = shodan_search.run("example.com")
    assert result["status"] == "no_findings"


def test_shodan_search_reports_real_indexed_services():
    payload = {"ports": [80, 443], "data": [{"port": 80, "product": "nginx", "data": "HTTP/1.1 200 OK"}], "vulns": []}
    with patch("socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", return_value=_fake_http_response(payload)):
        result = shodan_search.run("example.com", shodan_api_key="fake-key")
    assert result["status"] == "completed"
    assert "nginx" in result["findings"][0]["evidence"]


# ── censys_search.py ─────────────────────────────────────────────────────

def test_censys_search_requires_credentials_without_keys(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    result = censys_search.run("example.com")
    assert result["status"] == "requires_credentials"


def test_censys_search_reports_real_services():
    # Later migrated from the legacy Basic-Auth v2 API (censys_api_id/secret)
    # to the current Censys Platform API, authenticated with a free
    # Personal Access Token (censys_pat).
    payload = {"result": {"services": [{"port": 443, "service_name": "HTTPS", "software": [{"product": "nginx", "version": "1.20"}]}]}}
    with patch("socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.censys_search.safe_urlopen", return_value=_fake_http_response(payload)):
        result = censys_search.run("example.com", censys_pat="free-token-123")
    assert result["status"] == "completed"
    assert "nginx" in result["findings"][0]["evidence"]


# ── email_harvest.py ─────────────────────────────────────────────────────

def test_email_harvest_dns_failure_is_honest_failed():
    with patch("socket.gethostbyname", side_effect=socket.gaierror("no such host")):
        result = email_harvest.run("nonexistent.invalid")
    assert result["status"] == "failed"


def test_email_harvest_reports_missing_spf_dmarc_when_absent():
    with patch("socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.email_harvest._mx_records", return_value=["mx1.example.com"]), \
         patch("nexus.tools.reconnaissance.email_harvest._txt_records_via_dnspython", return_value=[]):
        result = email_harvest.run("example.com")
    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("No SPF record" in t for t in titles)
    assert any("No DMARC record" in t for t in titles)


def test_email_harvest_generates_patterns_for_named_employee():
    with patch("socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.email_harvest._mx_records", return_value=[]), \
         patch("nexus.tools.reconnaissance.email_harvest._txt_records_via_dnspython", return_value=["v=spf1 -all"]):
        result = email_harvest.run("example.com", employee_name="Jane Doe")
    assert result["status"] == "completed"
    assert any("jane.doe@example.com" in p for p in result["metadata"]["generated_email_patterns"])


# ── google_dorking.py ────────────────────────────────────────────────────

def test_google_dorking_generates_real_queries_not_fake_results():
    result = google_dorking.run("example.com")
    assert result["status"] == "completed"
    all_queries = [q for cat in result["metadata"]["dork_queries"].values() for q in cat]
    assert any("site:example.com filetype:pdf" in q for q in all_queries)
    assert any("inurl:admin" in q for q in all_queries)


def test_google_dorking_empty_target_fails_honestly():
    result = google_dorking.run("")
    assert result["status"] == "failed"


# ── social_osint.py ──────────────────────────────────────────────────────

def test_social_osint_reports_platform_presence():
    def fake_head(url, timeout=6):
        return 200 if "github.com" in url else 404
    with patch("nexus.tools.reconnaissance.social_osint._check_presence", side_effect=fake_head):
        result = social_osint.run("acme-corp")
    assert result["status"] == "completed"
    assert any("GitHub" in f["title"] for f in result["findings"])


def test_social_osint_no_findings_when_nothing_found():
    with patch("nexus.tools.reconnaissance.social_osint._check_presence", return_value=404):
        result = social_osint.run("totally-unknown-entity-xyz")
    assert result["status"] == "no_findings"
