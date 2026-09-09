"""Regression tests for target scope enforcement."""

import pytest

from nexus.foundation.config import config
from nexus.foundation.guardrails.scope_guard import ScopeGuard, ScopeGuardError


def test_exact_hostname_and_url_port_are_allowed(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost,example.test")
    assert ScopeGuard.validate("example.test")
    assert ScopeGuard.validate("https://example.test:8443/path")


def test_out_of_scope_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost,example.test")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("evil.example")


def test_wildcard_allows_subdomains_but_not_unrelated_hosts(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "*.example.test")
    assert ScopeGuard.validate("api.example.test")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("example.test")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("api.example.test.evil.test")


def test_ipv4_cidr(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "192.0.2.0/24")
    assert ScopeGuard.validate("192.0.2.10")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("192.0.3.10")


def test_ipv6_cidr(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "2001:db8::/32")
    assert ScopeGuard.validate("2001:db8::10")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("2001:db9::10")


def test_hostname_resolves_into_approved_cidr(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "192.0.2.0/24")
    monkeypatch.setattr(
        "nexus.foundation.guardrails.scope_guard.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("192.0.2.10", 0)),
            (2, 1, 6, "", ("192.0.2.11", 0)),
        ],
    )
    assert ScopeGuard.validate("scanner.example.test")


def test_hostname_with_any_out_of_scope_dns_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "192.0.2.0/24")
    monkeypatch.setattr(
        "nexus.foundation.guardrails.scope_guard.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("192.0.2.10", 0)),
            (2, 1, 6, "", ("198.51.100.10", 0)),
        ],
    )
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("scanner.example.test")


def test_dns_failure_does_not_silently_allow(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "192.0.2.0/24")

    def fail_resolution(*args, **kwargs):
        raise OSError("temporary DNS failure")

    monkeypatch.setattr(
        "nexus.foundation.guardrails.scope_guard.socket.getaddrinfo",
        fail_resolution,
    )
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("scanner.example.test")


def test_empty_scope_is_rejected(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("localhost")


def test_empty_and_malformed_targets_are_rejected(monkeypatch):
    monkeypatch.setattr(config, "nexus_allowed_targets", "localhost")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("")
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate("http://")
