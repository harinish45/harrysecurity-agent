"""``safe_urlopen()`` (nexus/foundation/net.py) is the single sanctioned
outbound-HTTP choke point used by ~280 tool files. It used to only validate
the URL *scheme* of the first request — ``urllib.request.urlopen()`` then
auto-followed any redirect with zero re-validation, so a genuinely in-scope
target could redirect a tool's request (via a plain 30x Location header) to
an out-of-scope or internal host, including the classic SSRF pivot to a
cloud-metadata endpoint (``169.254.169.254``). ``ScopeGuard.validate()`` was
only ever called once, by ``ToolExecutor``, against the *original* target
string — never against a redirect's destination.

These tests use real local HTTP servers (not mocks) so the actual
``urllib`` redirect-following machinery is exercised end-to-end, not just
the scope-check function in isolation.
"""
from __future__ import annotations

import http.server
import threading
import time

import pytest

from nexus.foundation.config import config
from nexus.foundation.net import SSRFBlockedError, safe_urlopen


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Configured per-test via class attributes rather than __init__ args,
    since http.server.HTTPServer constructs the handler itself per request."""

    redirect_to: str = ""

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok-final")

    def log_message(self, *a):  # noqa: D401 - silence default stderr logging in test output
        pass


@pytest.fixture
def local_server():
    """A real local HTTP server on an ephemeral port, torn down after the test."""
    handler_cls = type("Handler", (_RedirectHandler,), {})
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    try:
        yield server, handler_cls
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_redirect_to_cloud_metadata_address_is_blocked(local_server, monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    server, handler_cls = local_server
    handler_cls.redirect_to = "http://169.254.169.254/latest/meta-data/"

    with pytest.raises(SSRFBlockedError):
        safe_urlopen(f"http://127.0.0.1:{server.server_address[1]}/start", timeout=3)


def test_redirect_to_arbitrary_out_of_scope_host_is_blocked(local_server, monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    server, handler_cls = local_server
    handler_cls.redirect_to = "http://some-other-host.example.net/"

    with pytest.raises(SSRFBlockedError):
        safe_urlopen(f"http://127.0.0.1:{server.server_address[1]}/start", timeout=3)


def test_redirect_within_configured_scope_is_followed_normally(local_server, monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    server, handler_cls = local_server
    port = server.server_address[1]
    handler_cls.redirect_to = f"http://127.0.0.1:{port}/final"

    resp = safe_urlopen(f"http://127.0.0.1:{port}/start", timeout=3)
    assert resp.status == 200
    assert resp.read() == b"ok-final"


def test_redirect_permitted_under_wide_open_scope(local_server, monkeypatch):
    """A broad NEXUS_ALLOWED_TARGETS=0.0.0.0/0 authorises a redirect
    anywhere, exactly as it would authorise that host as an initial
    target — the redirect check reuses the operator's own configured
    scope, it does not invent a stricter policy on top of it."""
    monkeypatch.setattr(config, "nexus_allowed_targets", "0.0.0.0/0")
    server, handler_cls = local_server
    handler_cls.redirect_to = "http://169.254.169.254/"

    # Following succeeds up to the point urllib actually tries to reach
    # that address (which will fail/timeout in this sandboxed test
    # environment) — the important thing is it's not rejected by
    # SSRFBlockedError, i.e. the scope check itself passes it through.
    with pytest.raises(Exception) as exc_info:
        safe_urlopen(f"http://127.0.0.1:{server.server_address[1]}/start", timeout=2)
    assert not isinstance(exc_info.value, SSRFBlockedError)


def test_scheme_check_still_applies_to_redirect_target(local_server, monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    server, handler_cls = local_server
    handler_cls.redirect_to = "file:///etc/passwd"

    with pytest.raises(Exception):
        safe_urlopen(f"http://127.0.0.1:{server.server_address[1]}/start", timeout=3)


def test_ordinary_request_with_no_redirect_is_unaffected(local_server, monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    server, _handler_cls = local_server

    resp = safe_urlopen(f"http://127.0.0.1:{server.server_address[1]}/final", timeout=3)
    assert resp.status == 200
    assert resp.read() == b"ok-final"


@pytest.mark.slow
def test_real_https_request_against_a_live_target_still_works(monkeypatch):
    """The highest-traffic code path in the codebase — a real end-to-end
    smoke test against a live external host with no redirect involved."""
    monkeypatch.setattr(config, "nexus_allowed_targets", "example.com,0.0.0.0/0")
    resp = safe_urlopen("https://example.com/", timeout=10)
    assert resp.status == 200
    assert len(resp.read()) > 0
