"""Unit tests for nexus.advanced.neurosymbolic.NeuroSymbolicExplainer.

No live network/API keys required: the "no configured LLM provider" case
is exercised both via the module's real default-construction path (which
must never crash even when no LLM backend is reachable) and via an
explicit fake router, so the fact-checking behaviour itself is verified
deterministically without depending on sandbox network conditions.
"""
from __future__ import annotations

from nexus.advanced.neurosymbolic import NeuroSymbolicExplainer

FINDINGS = [
    {
        "title": "Outdated OpenSSH version",
        "severity": "high",
        "affected_asset": "10.0.0.5",
        "tool": "network.ssh_audit",
    },
    {
        "title": "Missing security headers",
        "severity": "medium",
        "affected_asset": "web.example.com",
        "tool": "network.http_headers",
    },
    {
        "title": "Self-signed TLS certificate",
        "severity": "low",
        "affected_asset": "10.0.0.5",
        "tool": "network.tls_scan",
    },
]


def test_explain_with_no_llm_router_falls_back_gracefully():
    """Passing llm_router=None triggers the module's own default
    LLMRouter() construction attempt. In a sandboxed test environment with
    no reachable provider, this must never raise, and must fall back to a
    valid symbolic-only summary."""
    explainer = NeuroSymbolicExplainer()
    result = explainer.explain(FINDINGS, llm_router=None)

    assert isinstance(result, dict)
    assert set(result.keys()) == {
        "explanation",
        "llm_available",
        "verified_claims",
        "unverified_claims",
        "graph_summary",
    }
    assert isinstance(result["explanation"], str) and result["explanation"]
    assert isinstance(result["llm_available"], bool)
    assert isinstance(result["graph_summary"], dict)
    assert result["graph_summary"]["nodes"] == 2  # two distinct affected_asset values
    assert "top_assets" in result["graph_summary"]


def test_explain_with_explicitly_unavailable_router_is_symbolic_only():
    """A router whose .complete() raises (simulating 'no provider
    configured') must produce a purely symbolic fallback: llm_available is
    False and no fact-check lists are populated."""

    class RaisingRouter:
        def complete(self, prompt, system=None, **kwargs):
            raise RuntimeError("no provider configured")

    explainer = NeuroSymbolicExplainer()
    result = explainer.explain(FINDINGS, llm_router=RaisingRouter())

    assert result["llm_available"] is False
    assert result["verified_claims"] == []
    assert result["unverified_claims"] == []
    assert "symbolic" in result["explanation"].lower() or "No LLM" in result["explanation"]


def test_explain_with_error_sentinel_response_is_treated_as_unavailable():
    """LLMRouter's real providers often return an '[ERROR] ...' sentinel
    string instead of raising -- that must be treated the same as a hard
    failure, not fact-checked as a genuine explanation."""

    class ErrorSentinelRouter:
        def complete(self, prompt, system=None, **kwargs):
            return "[ERROR] Connection refused"

    explainer = NeuroSymbolicExplainer()
    result = explainer.explain(FINDINGS, llm_router=ErrorSentinelRouter())

    assert result["llm_available"] is False
    assert result["verified_claims"] == []
    assert result["unverified_claims"] == []


def test_explain_verifies_real_claims_and_flags_fabricated_ones():
    """A fake LLM response that correctly cites a real asset/finding
    should be verified; a fabricated CVE it invents should show up as
    unverified."""

    class FakeRouter:
        def complete(self, prompt, system=None, **kwargs):
            return (
                "The asset '10.0.0.5' is affected by 'Outdated OpenSSH version', "
                "and is also vulnerable to CVE-2099-99999 which was not in the "
                "provided data."
            )

    explainer = NeuroSymbolicExplainer()
    result = explainer.explain(FINDINGS, llm_router=FakeRouter())

    assert result["llm_available"] is True
    assert any("10.0.0.5" in c for c in result["verified_claims"])
    assert any("Outdated OpenSSH version" in c for c in result["verified_claims"])
    assert "CVE-2099-99999" in result["unverified_claims"]


def test_explain_with_no_findings():
    explainer = NeuroSymbolicExplainer()

    class RaisingRouter:
        def complete(self, prompt, system=None, **kwargs):
            raise RuntimeError("no provider configured")

    result = explainer.explain([], llm_router=RaisingRouter())
    assert result["llm_available"] is False
    assert result["graph_summary"]["nodes"] == 0
    assert "No findings" in result["explanation"]
