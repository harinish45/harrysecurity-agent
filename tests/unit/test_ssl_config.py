import socket
import ssl

from nexus.foundation import ssl_config
from nexus.foundation.ssl_config import _is_private_scope, get_ssl_context


def test_default_context_is_always_verified():
    ctx = get_ssl_context("example.com")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_insecure_not_requested_stays_verified():
    ctx = get_ssl_context("127.0.0.1", allow_insecure=False)
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_insecure_allowed_for_loopback():
    ctx = get_ssl_context("127.0.0.1", allow_insecure=True)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_insecure_allowed_for_localhost_hostname():
    ctx = get_ssl_context("localhost", allow_insecure=True)
    assert ctx.verify_mode == ssl.CERT_NONE


def test_insecure_downgraded_to_secure_for_public_host():
    ctx = get_ssl_context("example.com", allow_insecure=True)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_env_override_allows_insecure_for_any_target(monkeypatch):
    monkeypatch.setenv("NEXUS_ALLOW_INSECURE_TLS", "1")
    ctx = get_ssl_context("example.com", allow_insecure=True)
    assert ctx.verify_mode == ssl.CERT_NONE


def test_url_target_extracts_hostname():
    ctx = get_ssl_context("https://127.0.0.1:8443/path", allow_insecure=True)
    assert ctx.verify_mode == ssl.CERT_NONE


def test_is_private_scope_recognises_private_ranges():
    assert _is_private_scope("10.0.0.5") is True
    assert _is_private_scope("192.168.1.1") is True
    assert _is_private_scope("127.0.0.1") is True


def test_is_private_scope_rejects_public_ip():
    assert _is_private_scope("8.8.8.8") is False


def test_is_private_scope_fails_closed_on_unresolvable_host(monkeypatch):
    # Never contact real DNS in tests — force the failure path directly.
    def _raise(*_args, **_kwargs):
        raise socket.gaierror("simulated resolution failure")

    monkeypatch.setattr(ssl_config.socket, "getaddrinfo", _raise)
    assert _is_private_scope("this-host-does-not-exist.invalid.") is False
