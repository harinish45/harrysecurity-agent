"""Real-logic tests for the 17 webapp.* "secondary" tools that an audit
found were byte-for-byte-logic-identical fake stubs (a DNS resolve + bare
GET of "/" regardless of the tool's actual name/purpose, in:
authorization_test, auth_test, browser_agent, business_logic, csrf,
file_upload, graphql, idor, jwt_analysis, param_discovery, rate_limit,
rest_api_testing, rfi, scanner, session_mgmt, traversal, waf_detect).

Each tool now performs real HTTP against `target`. To test that logic
deterministically (not against the live internet), this file spins up a
local `http.server`/`socketserver`-based HTTP server in a background
thread per test, serving crafted responses, and points each tool at
`127.0.0.1:<port>`.
"""
from __future__ import annotations

import http.server
import json
import socketserver
import threading
import urllib.parse
from contextlib import contextmanager

import pytest

from nexus.tools.webapp import (
    authorization_test,
    auth_test,
    browser_agent,
    business_logic,
    csrf,
    file_upload,
    graphql,
    idor,
    jwt_analysis,
    param_discovery,
    rate_limit,
    rest_api_testing,
    rfi,
    scanner,
    session_mgmt,
    traversal,
    waf_detect,
)


# ── Local scripted HTTP server ──────────────────────────────────────────────

class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_handler(router):
    """router: dict[(method, path)] -> callable(handler, query, body) -> None
    (the callable is responsible for calling send_response/send_header/
    end_headers/wfile.write itself, for full per-test flexibility)."""

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _dispatch(self, method):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""

            fn = router.get((method, path))
            if fn is None:
                # Fallback wildcard entry, useful for "match any unlisted path".
                fn = router.get((method, "*"))
            if fn is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            fn(self, query, body)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_OPTIONS(self):
            self._dispatch("OPTIONS")

        def do_HEAD(self):
            self._dispatch("HEAD")

    return Handler


def _send(handler, status=200, headers=None, body=b"", set_cookies=None):
    handler.send_response(status)
    for k, v in (headers or {}).items():
        handler.send_header(k, v)
    for cookie in (set_cookies or []):
        handler.send_header("Set-Cookie", cookie)
    if isinstance(body, str):
        body = body.encode("utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if body:
        handler.wfile.write(body)


@contextmanager
def run_server(router):
    handler_cls = _make_handler(router)
    server = _ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# ── webapp.csrf ──────────────────────────────────────────────────────────────

def test_csrf_flags_form_without_token_and_cookie_without_samesite():
    def root(h, q, b):
        html = """<html><body>
        <form method="POST" action="/submit">
            <input type="text" name="name">
            <input type="submit">
        </form>
        </body></html>"""
        _send(h, 200, {"Content-Type": "text/html"}, html, set_cookies=["session=abc123; Path=/"])

    with run_server({("GET", "/"): root}) as target:
        result = csrf.run(target)

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("without CSRF token" in t for t in titles)
    assert any("SameSite" in t for t in titles)


def test_csrf_no_findings_when_token_and_samesite_present():
    def root(h, q, b):
        html = """<html><body>
        <form method="POST" action="/submit">
            <input type="hidden" name="csrf_token" value="xyz">
            <input type="text" name="name">
        </form>
        </body></html>"""
        _send(h, 200, {"Content-Type": "text/html"}, html, set_cookies=["session=abc123; Path=/; SameSite=Strict"])

    with run_server({("GET", "/"): root}) as target:
        result = csrf.run(target)

    assert result["status"] == "no_findings"


# ── webapp.session_mgmt ──────────────────────────────────────────────────────

def test_session_mgmt_flags_missing_httponly_and_samesite():
    def root(h, q, b):
        _send(h, 200, {"Content-Type": "text/html"}, "hi", set_cookies=["sessionid=deadbeef; Path=/"])

    with run_server({("GET", "/"): root}) as target:
        result = session_mgmt.run(target)

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)


def test_session_mgmt_no_findings_with_fully_flagged_cookie():
    def root(h, q, b):
        _send(h, 200, {}, "hi", set_cookies=["sessionid=deadbeef; Path=/; HttpOnly; SameSite=Strict"])

    with run_server({("GET", "/"): root}) as target:
        result = session_mgmt.run(target)

    assert result["status"] == "no_findings"


# ── webapp.jwt_analysis ───────────────────────────────────────────────────────

def _b64url(d: dict) -> str:
    import base64
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_jwt_analysis_finds_alg_none_token_in_body():
    token = f"{_b64url({'alg': 'none', 'typ': 'JWT'})}.{_b64url({'sub': '1', 'role': 'user'})}."

    def root(h, q, b):
        _send(h, 200, {"Content-Type": "text/html"}, f"<html>token={token}</html>")

    with run_server({("GET", "/"): root}) as target:
        result = jwt_analysis.run(target)

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("alg='none'" in t for t in titles)
    assert any("no 'exp'" in t for t in titles)


def test_jwt_analysis_no_findings_when_no_token_present():
    def root(h, q, b):
        _send(h, 200, {}, "no tokens here")

    with run_server({("GET", "/"): root}) as target:
        result = jwt_analysis.run(target)

    assert result["status"] == "no_findings"


# ── webapp.traversal ──────────────────────────────────────────────────────────

def test_traversal_detects_etc_passwd_signature():
    def catch_all(h, q, b):
        if "etc/passwd" in h.path or "etc%2fpasswd" in h.path.lower():
            _send(h, 200, {}, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        else:
            _send(h, 404, {}, "not found")

    with run_server({("GET", "*"): catch_all}) as target:
        result = traversal.run(target)

    assert result["status"] == "completed"
    assert any("Path traversal" in f["title"] for f in result["findings"])


def test_traversal_no_findings_when_all_404():
    def catch_all(h, q, b):
        _send(h, 404, {}, "not found")

    with run_server({("GET", "*"): catch_all}) as target:
        result = traversal.run(target)

    assert result["status"] == "no_findings"


# ── webapp.rfi ────────────────────────────────────────────────────────────────

def test_rfi_detects_stream_open_failure_indicator():
    def catch_all(h, q, b):
        query = urllib.parse.urlparse(h.path).query
        params = urllib.parse.parse_qs(query)
        if any("example.com" in v for vals in params.values() for v in vals):
            _send(h, 500, {}, "Warning: failed to open stream: http request failed! in /var/www/index.php")
        else:
            _send(h, 200, {}, "normal page")

    with run_server({("GET", "*"): catch_all}) as target:
        result = rfi.run(target)

    assert result["status"] == "completed"
    assert any("Remote File Inclusion" in f["title"] for f in result["findings"])


# ── webapp.idor ────────────────────────────────────────────────────────────────

def test_idor_flags_adjacent_numeric_id_with_similar_response():
    def handler(h, q, b):
        # Every numeric-id page returns near-identical content regardless of id
        # (i.e. no access control) — this should be flagged.
        _send(h, 200, {}, "<html>User profile: user data goes here, name and email etc.</html>")

    with run_server({("GET", "*"): handler}) as target:
        result = idor.run(f"{target}/user/1000?id=1000")

    assert result["status"] == "completed"
    assert any("IDOR" in f["title"] for f in result["findings"])


def test_idor_no_findings_when_no_numeric_reference_present():
    def root(h, q, b):
        _send(h, 200, {}, "<html>static homepage, no ids here</html>")

    with run_server({("GET", "/"): root}) as target:
        result = idor.run(target)

    assert result["status"] == "no_findings"
    assert result["metadata"]["candidates_found"] == 0


# ── webapp.param_discovery ────────────────────────────────────────────────────

def test_param_discovery_flags_debug_param_that_changes_response():
    def root(h, q, b):
        if "debug" in q:
            _send(h, 200, {}, "<html>" + "DEBUG MODE VERBOSE STACK TRACE OUTPUT " * 20 + "</html>")
        else:
            _send(h, 200, {}, "<html>normal small page</html>")

    with run_server({("GET", "/"): root}) as target:
        result = param_discovery.run(target, wordlist=["debug", "page", "id"])

    assert result["status"] == "completed"
    discovered_params = [d["param"] for d in result["metadata"]["discovered"]]
    assert "debug" in discovered_params


def test_param_discovery_no_findings_when_nothing_changes():
    def root(h, q, b):
        _send(h, 200, {}, "<html>always the same</html>")

    with run_server({("GET", "/"): root}) as target:
        result = param_discovery.run(target, wordlist=["debug", "page", "id"])

    assert result["status"] == "no_findings"


# ── webapp.rate_limit ──────────────────────────────────────────────────────────

def test_rate_limit_flags_absence_of_throttling():
    def root(h, q, b):
        _send(h, 200, {}, "ok")

    with run_server({("GET", "/"): root}) as target:
        result = rate_limit.run(target, burst_size=10)

    assert result["status"] == "completed"
    assert any("No rate limiting" in f["title"] for f in result["findings"])
    assert result["metadata"]["successful_requests"] == 10


def test_rate_limit_detects_429_throttling():
    counter = {"n": 0}

    def root(h, q, b):
        counter["n"] += 1
        if counter["n"] > 3:
            _send(h, 429, {"Retry-After": "5"}, "too many requests")
        else:
            _send(h, 200, {}, "ok")

    with run_server({("GET", "/"): root}) as target:
        result = rate_limit.run(target, burst_size=10)

    assert result["status"] == "no_findings"  # protective control present
    assert result["metadata"]["throttled_requests"] > 0


# ── webapp.waf_detect ────────────────────────────────────────────────────────

def test_waf_detect_identifies_cloudflare_by_header():
    def root(h, q, b):
        _send(h, 200, {"Server": "cloudflare", "CF-RAY": "abc123-SJC"}, "ok")

    with run_server({("GET", "*"): root}) as target:
        result = waf_detect.run(target)

    assert result["status"] == "completed"
    assert any("Cloudflare" in f["title"] for f in result["findings"])


def test_waf_detect_flags_no_waf_when_nothing_matches_and_no_blocking():
    def root(h, q, b):
        _send(h, 200, {}, "ok")

    with run_server({("GET", "*"): root}) as target:
        result = waf_detect.run(target)

    assert result["status"] == "completed"
    assert any("No WAF" in f["title"] for f in result["findings"])


# ── webapp.graphql ─────────────────────────────────────────────────────────────

def test_graphql_detects_introspection_enabled():
    def gql(h, q, b):
        payload = json.loads(b.decode())
        assert "__schema" in payload["query"]
        resp = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                    "types": [{"name": "User", "kind": "OBJECT"}, {"name": "Query", "kind": "OBJECT"}],
                }
            }
        }
        _send(h, 200, {"Content-Type": "application/json"}, json.dumps(resp))

    with run_server({("POST", "/graphql"): gql}) as target:
        result = graphql.run(target, paths=["/graphql"])

    assert result["status"] == "completed"
    assert any("introspection is ENABLED" in f["title"] for f in result["findings"])


def test_graphql_no_findings_when_no_endpoint_exists():
    with run_server({}) as target:
        result = graphql.run(target, paths=["/graphql"])

    assert result["status"] == "no_findings"


# ── webapp.rest_api_testing ────────────────────────────────────────────────────

def test_rest_api_testing_finds_openapi_spec_and_risky_methods():
    def openapi(h, q, b):
        _send(h, 200, {"Content-Type": "application/json"}, json.dumps({"openapi": "3.0.0", "paths": {}}))

    def options(h, q, b):
        _send(h, 200, {"Allow": "GET, POST, PUT, DELETE, TRACE"}, "")

    with run_server({("GET", "/openapi.json"): openapi, ("OPTIONS", "/"): options}) as target:
        result = rest_api_testing.run(target, paths=["/openapi.json"])

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("specification" in t for t in titles)
    assert any("risky" in t.lower() for t in titles)


# ── webapp.file_upload ────────────────────────────────────────────────────────

def test_file_upload_discovers_endpoint_without_uploading():
    def upload(h, q, b):
        assert b == b""  # discovery-only: never sends a body
        _send(h, 200, {"Allow": "POST, OPTIONS"}, "")

    with run_server({("OPTIONS", "/api/upload"): upload}) as target:
        result = file_upload.run(target, paths=["/api/upload"])

    assert result["status"] == "completed"
    assert any("upload endpoint discovered" in f["title"].lower() for f in result["findings"])


def test_file_upload_no_findings_when_nothing_found():
    with run_server({}) as target:
        result = file_upload.run(target, paths=["/api/upload"])

    assert result["status"] == "no_findings"


# ── webapp.auth_test / webapp.authorization_test (genuinely different checks) ──

def test_auth_test_finds_login_form_and_basic_challenge():
    def root(h, q, b):
        _send(h, 401, {"WWW-Authenticate": "Basic realm=\"test\""}, "unauthorized")

    def login(h, q, b):
        html = '<form method="POST" action="/login"><input type="password" name="pw"></form>'
        _send(h, 200, {}, html)

    with run_server({("GET", "/"): root, ("GET", "/login"): login}) as target:
        result = auth_test.run(target, paths=["/login"])

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("Basic authentication challenge" in t for t in titles)
    assert any("Login endpoint discovered" in t for t in titles)
    assert any("plaintext HTTP" in t for t in titles)  # http:// target + password field


def test_authorization_test_flags_unauthenticated_admin_access():
    def admin(h, q, b):
        _send(h, 200, {}, "<html>Admin Dashboard - Welcome</html>")

    with run_server({("GET", "/admin"): admin}) as target:
        result = authorization_test.run(target, paths=["/admin"])

    assert result["status"] == "completed"
    assert any("without authentication" in f["title"] for f in result["findings"])


def test_authorization_test_no_finding_when_properly_gated():
    def admin(h, q, b):
        _send(h, 403, {}, "forbidden")

    with run_server({("GET", "/admin"): admin}) as target:
        result = authorization_test.run(target, paths=["/admin"])

    assert result["status"] == "no_findings"


def test_auth_test_and_authorization_test_are_not_duplicate_logic():
    """The task explicitly requires these two tools to genuinely differ, not
    just be renamed copies of the fake stub. Assert their source modules
    implement distinct probing logic (different path lists / different
    core checks), not merely different docstrings."""
    assert auth_test.LOGIN_PATHS != authorization_test.PRIVILEGED_PATHS
    assert auth_test.run.__module__ != authorization_test.run.__module__


# ── webapp.business_logic ───────────────────────────────────────────────────────

def test_business_logic_flags_negative_quantity_accepted():
    def root(h, q, b):
        html = '<form method="POST" action="/cart"><input type="number" name="quantity" value="1"></form>'
        _send(h, 200, {}, html)

    def cart(h, q, b):
        _send(h, 200, {}, "order accepted")

    with run_server({("GET", "/"): root, ("POST", "/cart"): cart}) as target:
        result = business_logic.run(target)

    assert result["status"] == "completed"
    assert any("Negative value accepted" in f["title"] for f in result["findings"])


def test_business_logic_honest_no_findings_without_numeric_form():
    def root(h, q, b):
        _send(h, 200, {}, "<html>no forms at all here</html>")

    with run_server({("GET", "/"): root}) as target:
        result = business_logic.run(target)

    assert result["status"] == "no_findings"
    assert result["metadata"]["forms_with_numeric_fields"] == 0


# ── webapp.browser_agent ────────────────────────────────────────────────────────

def test_browser_agent_honestly_reports_unavailable_without_playwright(monkeypatch):
    monkeypatch.setattr(browser_agent, "_playwright_available", lambda: False)

    def root(h, q, b):
        _send(h, 200, {}, "ok")

    with run_server({("GET", "/"): root}) as target:
        result = browser_agent.run(target)

    assert result["status"] == "unavailable"
    assert "playwright" in result["error"].lower()
    assert result["metadata"]["playwright_installed"] is False


# ── webapp.scanner (aggregator) ─────────────────────────────────────────────────

def test_scanner_aggregates_multiple_real_subtool_findings(monkeypatch):
    """scanner.py calls other tools through tool_registry.run(), which goes
    through the full guardrail chain (ScopeGuard/LegalGuard/etc). Configure
    the environment the same way tests/unit/test_tool_registry_run.py does."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")

    def root(h, q, b):
        html = '<form method="POST" action="/submit"><input type="text" name="x"></form>'
        _send(h, 200, {"Content-Type": "text/html"}, html, set_cookies=["session=abc; Path=/"])

    with run_server({("GET", "*"): root}) as target:
        monkeypatch.setenv("NEXUS_ALLOWED_TARGETS", target.split(":")[0])
        result = scanner.run(target, subscans=["webapp.csrf", "webapp.session_mgmt"], timeout=5)

    assert result["status"] in ("completed", "no_findings")
    assert len(result["metadata"]["subscans"]) == 2
    for sub in result["metadata"]["subscans"]:
        assert sub["status"] != "failed", f"subscan {sub} unexpectedly failed: {result['metadata'].get('errors')}"
    # csrf.run and session_mgmt.run should each have real findings against this fixture
    assert result["status"] == "completed"
    assert len(result["findings"]) >= 2


def test_scanner_fails_cleanly_when_target_unreachable(monkeypatch):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    monkeypatch.setenv("NEXUS_ALLOWED_TARGETS", "127.0.0.1")
    # Port with nothing listening.
    result = scanner.run("127.0.0.1:1", subscans=["webapp.csrf"], timeout=2)
    assert result["status"] == "failed"
