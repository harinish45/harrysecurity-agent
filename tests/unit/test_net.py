import urllib.request

import pytest

from nexus.foundation.net import UnsupportedSchemeError, safe_urlopen


def test_rejects_file_scheme():
    with pytest.raises(UnsupportedSchemeError):
        safe_urlopen("file:///etc/passwd")


def test_rejects_ftp_scheme():
    with pytest.raises(UnsupportedSchemeError):
        safe_urlopen("ftp://example.com/secret")


def test_rejects_schemeless_string():
    with pytest.raises(UnsupportedSchemeError):
        safe_urlopen("not-a-url-at-all")


def test_rejects_request_object_with_bad_scheme():
    req = urllib.request.Request("file:///etc/shadow")
    with pytest.raises(UnsupportedSchemeError):
        safe_urlopen(req)


def test_allows_http_and_https_schemes_through_to_urlopen(monkeypatch):
    # safe_urlopen() now builds its own opener (rather than calling
    # urllib.request.urlopen() directly) so it can install a custom
    # HTTPRedirectHandler that re-validates every redirect hop against
    # ScopeGuard (see test_ssrf_redirect_protection.py) — OpenerDirector.open
    # is the real call that ends up executing the request either way, so
    # that's the layer to intercept here.
    calls = []

    def _fake_open(self, fullurl, data=None, timeout=None):
        calls.append((fullurl, timeout))
        return "opened"

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _fake_open)

    assert safe_urlopen("https://example.com", timeout=5) == "opened"
    assert safe_urlopen("http://example.com", timeout=3) == "opened"
    assert len(calls) == 2
