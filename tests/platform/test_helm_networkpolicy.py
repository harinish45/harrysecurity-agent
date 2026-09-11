"""Regression tests for deploy/helm/nexus-strike's NetworkPolicy template.

Guards against a critical bug where the default value of
`networkPolicy.allowedIngressNamespaceSelector` ({}) rendered as
`namespaceSelector: { matchLabels: {} }`. Per the Kubernetes API, an empty
label selector matches ALL objects, so that default silently meant "allow
ingress on the service port from every pod in every namespace in the
cluster" instead of the "no extra namespaces" the empty braces suggest.

These tests render the real chart with `helm template` and assert on the
actual rendered YAML, so they fail if the template regresses back to
emitting an unqualified/empty namespaceSelector.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "nexus-strike"

HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(HELM is None, reason="helm binary not available")


def _render_networkpolicy(*extra_set: str) -> dict:
    args = [
        HELM,
        "template",
        "nexus-strike",
        str(CHART_DIR),
        "-s",
        "templates/networkpolicy.yaml",
        # secrets.existingSecret has no default in values.yaml; supply one so
        # helm can render templates/secret.yaml too (helm renders the whole
        # chart before filtering to -s). Unrelated to the policy under test.
        "--set",
        "secrets.existingSecret=dummy",
    ]
    for value in extra_set:
        args += ["--set", value]
    result = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    assert result.returncode == 0, f"helm template failed: {result.stderr}"
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    assert len(docs) == 1
    return docs[0]


def _ingress_peers(policy: dict) -> list[dict]:
    return policy["spec"]["ingress"][0]["from"]


def test_default_values_do_not_allow_ingress_from_every_namespace():
    """The exact bug: default values must NOT render an empty/all-matching
    namespaceSelector as an ingress peer."""
    policy = _render_networkpolicy()
    peers = _ingress_peers(policy)

    for peer in peers:
        if "namespaceSelector" in peer:
            selector = peer["namespaceSelector"] or {}
            match_labels = selector.get("matchLabels")
            match_expressions = selector.get("matchExpressions")
            is_match_all = not match_labels and not match_expressions
            assert not is_match_all, (
                "an ingress peer renders an empty/absent namespaceSelector, "
                "which Kubernetes treats as 'match every namespace in the "
                f"cluster': {peer!r}"
            )


def test_default_values_restrict_ingress_to_same_namespace():
    """Default behaviour should be scoped to the release's own namespace:
    a podSelector peer with no namespaceSelector alongside it."""
    policy = _render_networkpolicy()
    peers = _ingress_peers(policy)

    same_namespace_peers = [p for p in peers if "podSelector" in p and "namespaceSelector" not in p]
    assert same_namespace_peers, (
        f"expected a same-namespace-only peer (podSelector with no "
        f"namespaceSelector); got {peers!r}"
    )
    # No peer should additionally open things up cluster-wide by default.
    assert not any("namespaceSelector" in p for p in peers)


def test_explicit_non_empty_selector_is_still_honored():
    """Operators must still be able to opt in to specific extra namespaces."""
    policy = _render_networkpolicy(
        "networkPolicy.allowedIngressNamespaceSelector.team=trusted"
    )
    peers = _ingress_peers(policy)

    namespace_peers = [p for p in peers if "namespaceSelector" in p]
    assert len(namespace_peers) == 1
    selector = namespace_peers[0]["namespaceSelector"]
    assert selector == {"matchLabels": {"team": "trusted"}}

    # Same-namespace access must still be present alongside the opt-in.
    assert any("podSelector" in p and "namespaceSelector" not in p for p in peers)
