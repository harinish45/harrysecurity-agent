"""Regression tests for the nexus-strike Helm chart's pod security posture.

Covers a real correctness/security bug: podSecurityContext previously set
only seccompProfile, with no fsGroup. Many dynamic volume provisioners create
a new PV's root directory owned by root:root with restrictive permissions
(0750/0755). Without fsGroup, kubelet has no instruction to chgrp the volume
to a GID the non-root container can write to, so first-boot writes to the
vault mount (NEXUS_VAULT_DIR, backed by the nexus-state PVC) can fail with a
permissions error depending on the cluster's CSI driver/storage-class
defaults, even though runAsNonRoot/allowPrivilegeEscalation/capabilities are
otherwise hardened.
"""

import re
from pathlib import Path

import pytest
import yaml

CHART_DIR = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "nexus-strike"
VALUES_PATH = CHART_DIR / "values.yaml"
DEPLOYMENT_TEMPLATE_PATH = CHART_DIR / "templates" / "deployment.yaml"


def _load_values() -> dict:
    return yaml.safe_load(VALUES_PATH.read_text(encoding="utf-8"))


def test_pod_security_context_sets_fsgroup():
    """fsGroup must be present and a real non-root GID (not 0/root)."""
    values = _load_values()
    pod_security_context = values["podSecurityContext"]

    assert "fsGroup" in pod_security_context, (
        "podSecurityContext is missing fsGroup: the non-root container may be "
        "unable to write to a freshly provisioned vault PVC depending on the "
        "cluster's default volume ownership."
    )

    fs_group = pod_security_context["fsGroup"]
    assert isinstance(fs_group, int) and not isinstance(fs_group, bool)
    assert fs_group > 0, "fsGroup of 0 would mean the group is root, defeating the fix"


def test_pod_security_context_keeps_existing_seccomp_hardening():
    """The fix must be additive: it should not regress the existing seccomp setting."""
    values = _load_values()
    pod_security_context = values["podSecurityContext"]

    assert pod_security_context["seccompProfile"]["type"] == "RuntimeDefault"


def test_deployment_template_propagates_podSecurityContext_wholesale():
    """
    The deployment template must render the *entire* podSecurityContext map
    (via `toYaml .Values.podSecurityContext`) rather than templating out
    individual fields, so that fsGroup (and any future field added to
    values.yaml) actually reaches the rendered Pod spec instead of being
    silently dropped by a hand-written field list.
    """
    template_text = DEPLOYMENT_TEMPLATE_PATH.read_text(encoding="utf-8")

    match = re.search(
        r"securityContext:\s*\n\s*\{\{-\s*toYaml\s+\.Values\.podSecurityContext\s*\|",
        template_text,
    )
    assert match is not None, (
        "expected the pod-level securityContext block to dump "
        "`.Values.podSecurityContext` wholesale via toYaml"
    )


def test_rendered_pod_manifest_includes_fsgroup_when_helm_available():
    """
    End-to-end confirmation: if the `helm` CLI is on PATH, actually render the
    chart and assert fsGroup shows up in the Pod's securityContext. Skipped
    (not failed) when helm isn't installed, since the two tests above already
    pin the source-level contract.
    """
    import shutil
    import subprocess

    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm CLI not available in this environment")

    result = subprocess.run(
        [helm, "template", "nexus-strike-test", str(CHART_DIR)],
        capture_output=True,
        text=True,
        check=True,
    )
    rendered_docs = list(yaml.safe_load_all(result.stdout))
    deployments = [doc for doc in rendered_docs if doc and doc.get("kind") == "Deployment"]
    assert deployments, "expected the chart to render a Deployment"

    pod_security_context = deployments[0]["spec"]["template"]["spec"]["securityContext"]
    assert pod_security_context.get("fsGroup") == _load_values()["podSecurityContext"]["fsGroup"]
