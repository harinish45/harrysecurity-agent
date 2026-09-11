"""Regression test for a real security gap in the Helm chart's pod spec:

deploy/helm/nexus-strike/templates/deployment.yaml never set
`automountServiceAccountToken: false`, so the namespace's default
ServiceAccount token was auto-mounted into a container that never talks to
the Kubernetes API. This app scans/exploits external targets and feeds tool
output back into an LLM-driven agent loop (a classic RCE-via-untrusted-input
surface); if an attacker achieves code execution inside the container, the
auto-mounted token at /var/run/secrets/kubernetes.io/serviceaccount/token
would let them talk to the in-cluster API server as the `default`
ServiceAccount for free reconnaissance/lateral movement -- a capability the
app has no legitimate need for, and inconsistent with the otherwise careful
pod/container securityContext hardening in the same file.

The chart's templates use Go template directives ({{ ... }}), so they are
not valid standalone YAML and can't be round-tripped through yaml.safe_load
without a running `helm template` (not available in this environment). These
tests instead assert directly on the rendered-adjacent structure of the pod
spec block in the source template, which is what actually controls the
generated manifest.
"""
from pathlib import Path

import pytest

DEPLOYMENT_YAML = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "helm"
    / "nexus-strike"
    / "templates"
    / "deployment.yaml"
)


@pytest.fixture(scope="module")
def deployment_text():
    return DEPLOYMENT_YAML.read_text(encoding="utf-8")


def _pod_spec_block(text: str) -> str:
    """Return the pod template's `spec:` block (the second, 4-space-indented
    `spec:` -- the Deployment's top-level `spec:` at 0 indent is the first),
    up to (but not including) the `containers:` list, i.e. everything that
    is a direct sibling of `securityContext:` and `containers:` at the pod
    level."""
    marker = "\n    spec:\n"
    start = text.index(marker) + len(marker)
    end = text.index("\n      containers:", start)
    return text[start:end]


def test_pod_spec_disables_automount_of_default_service_account_token(deployment_text):
    pod_spec = _pod_spec_block(deployment_text)
    assert "automountServiceAccountToken: false" in pod_spec, (
        "Pod spec must set automountServiceAccountToken: false so the "
        "default ServiceAccount's Kubernetes API token is not mounted into "
        "a container with no legitimate need to talk to the API server."
    )


def test_automount_directive_is_a_direct_pod_spec_sibling_not_in_container(deployment_text):
    """Guard against a regression where the field gets moved (e.g. nested
    under containers[].securityContext, where it has no effect) instead of
    living at the pod spec level."""
    pod_spec = _pod_spec_block(deployment_text)
    for line in pod_spec.splitlines():
        if "automountServiceAccountToken" in line:
            # Sibling of `securityContext:`/`containers:`, which sit at 6
            # spaces of indent directly under the pod's `spec:` (4 spaces).
            assert line.startswith("      automountServiceAccountToken:"), (
                f"expected 6-space pod-spec-level indent, got: {line!r}"
            )
            assert line.strip() == "automountServiceAccountToken: false"
            break
    else:
        pytest.fail("automountServiceAccountToken not found in pod spec block")


def test_automount_directive_appears_exactly_once(deployment_text):
    assert deployment_text.count("automountServiceAccountToken") == 1


def test_container_securityContext_hardening_still_present(deployment_text):
    """Sanity check that this fix didn't disturb the pre-existing hardening
    (runAsNonRoot/readOnlyRootFilesystem/drop ALL/seccomp) referenced by the
    finding as the standard this chart already holds itself to."""
    assert "{{- toYaml .Values.podSecurityContext | nindent 8 }}" in deployment_text
    assert "{{- toYaml .Values.securityContext | nindent 12 }}" in deployment_text
