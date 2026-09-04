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
    calls = []

    def _fake_urlopen(url_or_request, timeout=None, context=None, **kwargs):
        calls.append((url_or_request, timeout, context))
        return "opened"

    monkeypatch.setattr("nexus.foundation.net.urllib.request.urlopen", _fake_urlopen)

    assert safe_urlopen("https://example.com", timeout=5) == "opened"
    assert safe_urlopen("http://example.com", timeout=3) == "opened"
    assert len(calls) == 2
