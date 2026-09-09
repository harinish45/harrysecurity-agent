"""All 9 nexus/tools/compliance/*.py files used to be byte-for-byte
identical (a generic DNS+4-header check duplicated under 9 framework
names, confirmed via `diff pci_dss_audit.py gdpr_audit.py`) — caught
during this session's audit. Each now has real, framework-specific,
network-observable logic; these tests prove each tool's findings
genuinely vary based on mocked responses, not just "doesn't crash"."""
from unittest.mock import MagicMock, patch

from nexus.tools.compliance import (
    gdpr_audit,
    hipaa_audit,
    iso27001_audit,
    nist_800_53_audit,
    nist_csf_audit,
    pci_dss_audit,
    policy_reviews,
    risk_assessments,
    security_audits,
)


def _http_response(status=200, headers=None, body=b"", url="http://target/"):
    resp = MagicMock()
    resp.status = status
    resp.headers = MagicMock()
    headers = headers or {}
    resp.headers.get = lambda k, default=None: headers.get(k, default)
    resp.headers.get_all = lambda k, default=None: headers.get(k, default or [])
    resp.headers.__contains__ = lambda self, k: k in headers
    resp.read = lambda n=-1: body
    resp.geturl = lambda: url
    return resp


# ── pci_dss_audit ─────────────────────────────────────────────────────────

def test_pci_dss_flags_weak_tls_protocol():
    fake_tls_sock = MagicMock()
    fake_tls_sock.version.return_value = "TLSv1"
    fake_tls_sock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384",)
    fake_raw = MagicMock()
    fake_raw.__enter__.return_value = fake_raw
    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value.__enter__.return_value = fake_tls_sock

    with patch("socket.create_connection", return_value=fake_raw), \
         patch("nexus.tools.compliance.pci_dss_audit.get_ssl_context", return_value=fake_ctx), \
         patch("nexus.tools.compliance.pci_dss_audit.safe_urlopen", side_effect=OSError("no http")):
        result = pci_dss_audit.run("example.com")

    assert any("weak TLS protocol TLSv1" in f for f in result["findings"])


def test_pci_dss_accepts_strong_tls():
    fake_tls_sock = MagicMock()
    fake_tls_sock.version.return_value = "TLSv1.3"
    fake_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384",)
    fake_raw = MagicMock()
    fake_raw.__enter__.return_value = fake_raw
    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value.__enter__.return_value = fake_tls_sock

    with patch("socket.create_connection", return_value=fake_raw), \
         patch("nexus.tools.compliance.pci_dss_audit.get_ssl_context", return_value=fake_ctx), \
         patch("nexus.tools.compliance.pci_dss_audit.safe_urlopen", side_effect=OSError("no http")):
        result = pci_dss_audit.run("example.com")

    assert not any("violation" in f for f in result["findings"])


def test_pci_dss_detects_payment_form_over_http():
    with patch("socket.create_connection", side_effect=OSError("no tls")), \
         patch("nexus.tools.compliance.pci_dss_audit.safe_urlopen",
               return_value=_http_response(body=b'<input name="cardnumber">')):
        result = pci_dss_audit.run("example.com")

    assert any("payment-field-shaped form" in f for f in result["findings"])


# ── gdpr_audit ────────────────────────────────────────────────────────────

def test_gdpr_flags_precoconsent_cookies():
    resp = _http_response(headers={"Set-Cookie": ["session=abc; Path=/"]})
    with patch("nexus.tools.compliance.gdpr_audit.safe_urlopen", return_value=resp):
        result = gdpr_audit.run("example.com")
    assert any("before any" in f for f in result["findings"])


def test_gdpr_no_cookie_concern_when_none_set():
    resp = _http_response(headers={})
    with patch("nexus.tools.compliance.gdpr_audit.safe_urlopen", return_value=resp):
        result = gdpr_audit.run("example.com")
    assert any("No cookies set" in f for f in result["findings"])


# ── hipaa_audit ───────────────────────────────────────────────────────────

def test_hipaa_flags_cleartext_http():
    resp = _http_response(url="http://example.com/")
    with patch("nexus.tools.compliance.hipaa_audit.safe_urlopen", return_value=resp):
        result = hipaa_audit.run("example.com")
    assert any("violation" in f and "cleartext HTTP" in f for f in result["findings"])


def test_hipaa_flags_zero_max_age_hsts():
    def fake_urlopen(req, timeout=5):
        if str(req.full_url).startswith("http://"):
            return _http_response(url="https://example.com/")
        return _http_response(headers={"Strict-Transport-Security": "max-age=0"})

    with patch("nexus.tools.compliance.hipaa_audit.safe_urlopen", side_effect=fake_urlopen):
        result = hipaa_audit.run("example.com")
    assert any("max-age=0" in f for f in result["findings"])


# ── iso27001_audit ────────────────────────────────────────────────────────

def test_iso27001_maps_missing_headers_to_control_ids():
    resp = _http_response(headers={})
    with patch("nexus.tools.compliance.iso27001_audit.safe_urlopen", return_value=resp):
        result = iso27001_audit.run("example.com")
    assert any("[A.8.24]" in f and "MISSING" in f for f in result["findings"])


# ── nist_800_53_audit ────────────────────────────────────────────────────

def test_nist_800_53_flags_version_banner():
    def fake_urlopen(req, timeout=5):
        if "robots.txt" in str(req.full_url):
            import urllib.error
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)
        return _http_response(headers={"Server": "Apache/2.4.7 (Ubuntu)"})

    with patch("nexus.tools.compliance.nist_800_53_audit.safe_urlopen", side_effect=fake_urlopen):
        result = nist_800_53_audit.run("example.com")
    assert any("Apache/2.4.7" in f for f in result["findings"])


def test_nist_800_53_flags_sensitive_robots_disclosure():
    def fake_urlopen(req, timeout=5):
        if "robots.txt" in str(req.full_url):
            return _http_response(body=b"User-agent: *\nDisallow: /admin-panel/\n")
        return _http_response(headers={})

    with patch("nexus.tools.compliance.nist_800_53_audit.safe_urlopen", side_effect=fake_urlopen):
        result = nist_800_53_audit.run("example.com")
    assert any("/admin-panel/" in f for f in result["findings"])


# ── nist_csf_audit ────────────────────────────────────────────────────────

def test_nist_csf_flags_missing_spf_and_dmarc():
    with patch("nexus.tools.compliance.nist_csf_audit._txt_records", return_value=[]):
        result = nist_csf_audit.run("example.com")
    assert any("no SPF" in f for f in result["findings"])
    assert any("no DMARC" in f or "DMARC" in f for f in result["findings"])


def test_nist_csf_detects_present_spf():
    def fake_txt(target, timeout=5.0):
        if target == "example.com":
            return ["v=spf1 include:_spf.example.com ~all"]
        return []

    with patch("nexus.tools.compliance.nist_csf_audit._txt_records", side_effect=fake_txt):
        result = nist_csf_audit.run("example.com")
    assert any("SPF record present" in f for f in result["findings"])


# ── policy_reviews ────────────────────────────────────────────────────────

def test_policy_reviews_detects_security_txt_with_fields():
    def fake_urlopen(req, timeout=5):
        if "security.txt" in str(req.full_url):
            return _http_response(body=b"Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n")
        return _http_response(body=b"User-agent: *\n")

    with patch("nexus.tools.compliance.policy_reviews.safe_urlopen", side_effect=fake_urlopen):
        result = policy_reviews.run("example.com")
    assert any("security.txt found" in f for f in result["findings"])
    assert any("required field 'Contact'" in f for f in result["findings"])


def test_policy_reviews_reports_missing_security_txt():
    import urllib.error

    def fake_urlopen(req, timeout=5):
        if "security.txt" in str(req.full_url):
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)
        return _http_response(body=b"User-agent: *\n")

    with patch("nexus.tools.compliance.policy_reviews.safe_urlopen", side_effect=fake_urlopen):
        result = policy_reviews.run("example.com")
    assert any("No security.txt found" in f for f in result["findings"])


# ── risk_assessments ──────────────────────────────────────────────────────

def test_risk_assessments_aggregates_upstream_findings():
    upstream = [{"severity": "critical"}, {"severity": "low"}]
    with patch("socket.create_connection", side_effect=OSError("closed")):
        result = risk_assessments.run("example.com", findings=upstream)
    assert any("Aggregate risk score from 2 upstream" in f for f in result["findings"])


def test_risk_assessments_reports_open_ports():
    def fake_connect(addr, timeout=2):
        if addr[1] == 80:
            return MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False)
        raise OSError("closed")

    with patch("socket.create_connection", side_effect=fake_connect):
        result = risk_assessments.run("example.com")
    assert any("80" in f and "exposure" in f for f in result["findings"])


# ── security_audits ───────────────────────────────────────────────────────

def test_security_audits_flags_missing_headers():
    with patch("nexus.tools.compliance.security_audits.safe_urlopen", return_value=_http_response(headers={})):
        result = security_audits.run("example.com")
    assert any("missing" in f.lower() for f in result["findings"])


def test_security_audits_detects_directory_listing():
    def fake_urlopen(req, timeout=5):
        if "/assets/" in str(req.full_url):
            return _http_response(body=b"<title>Index of /assets/</title>")
        return _http_response(headers={
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
        })

    with patch("nexus.tools.compliance.security_audits.safe_urlopen", side_effect=fake_urlopen):
        result = security_audits.run("example.com")
    assert any("/assets/" in f for f in result["findings"])
