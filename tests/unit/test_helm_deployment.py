"""Regression test for the Helm deployment's secrets-vault env wiring.

nexus/foundation/secrets.py's ``_vault_dir()`` falls back to
``Path.home() / ".nexus"`` whenever ``NEXUS_VAULT_DIR`` is unset, then does
``path.mkdir(parents=True, exist_ok=True)`` unconditionally (not caught by
the "never raise" guarantee, which only covers ``SecretsManager.get()``).

The Helm chart's runtime image runs as a non-root user whose $HOME is not
the PVC mount, and the pod's ``securityContext.readOnlyRootFilesystem`` is
true (values.yaml), with only the PVC-backed path
(``.Values.persistence.mountPath``) writable. Without an explicit
``NEXUS_VAULT_DIR`` env var pointed at that mount, the first secret access
in a Helm-deployed pod raises ``OSError: Read-only file system``.

There is no ``helm`` binary in this environment, so this test asserts
directly against the chart's template/values source rather than a
``helm template`` render — it still catches the concrete regression (the
env var missing, or pointed somewhere other than the writable, persistent
mount) without requiring the Helm toolchain to be installed.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

CHART_DIR = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "nexus-strike"
DEPLOYMENT_TEMPLATE = CHART_DIR / "templates" / "deployment.yaml"
VALUES_FILE = CHART_DIR / "values.yaml"


def _deployment_source() -> str:
    return DEPLOYMENT_TEMPLATE.read_text(encoding="utf-8")


def _container_block(source: str) -> str:
    """Return the single container's spec, from its `- name:` to the next
    top-level (2-space-indented) `- name:` or the `volumes:` sibling key."""
    match = re.search(
        r"containers:\n(?P<body>.*?)\n {6}volumes:\n",
        source,
        re.DOTALL,
    )
    assert match, "could not isolate the containers: block in deployment.yaml"
    return match.group("body")


def test_values_yaml_is_well_formed_and_has_persistence_mount_path():
    values = yaml.safe_load(VALUES_FILE.read_text(encoding="utf-8"))
    assert values["persistence"]["mountPath"], "persistence.mountPath must be set"


def test_deployment_sets_nexus_vault_dir_env_var():
    """The container must declare an env: block with NEXUS_VAULT_DIR — the
    regression was that no env/envFrom existed anywhere in the container
    spec at all."""
    container = _container_block(_deployment_source())
    assert re.search(r"\benv:\s*\n", container), (
        "container spec has no env: block; NEXUS_VAULT_DIR is not set, so "
        "SecretsManager falls back to $HOME/.nexus on first secret access"
    )
    assert "NEXUS_VAULT_DIR" in container, (
        "container env: block exists but doesn't set NEXUS_VAULT_DIR"
    )


def test_nexus_vault_dir_points_at_the_writable_persistent_mount():
    """The vault dir must resolve to exactly the same path as the PVC
    volumeMount (.Values.persistence.mountPath), not a literal path that
    could drift from it, and not the container's (read-only, unmounted)
    $HOME."""
    source = _deployment_source()
    container = _container_block(source)

    env_value_match = re.search(
        r"-\s*name:\s*NEXUS_VAULT_DIR\s*\n\s*value:\s*(?P<expr>.+)",
        container,
    )
    assert env_value_match, "NEXUS_VAULT_DIR env entry not in `- name: ... value: ...` form"
    env_expr = env_value_match.group("expr").strip()

    mount_path_match = re.search(
        r"-\s*name:\s*nexus-state\s*\n\s*mountPath:\s*(?P<expr>.+)",
        container,
    )
    assert mount_path_match, "no volumeMounts entry named nexus-state found for the container"
    mount_expr = mount_path_match.group("expr").strip()

    # Both must be driven by the same Helm value (persistence.mountPath),
    # not independently-hardcoded strings that could silently diverge.
    assert ".Values.persistence.mountPath" in env_expr, (
        f"NEXUS_VAULT_DIR value {env_expr!r} is not templated off "
        "persistence.mountPath, so it can drift from the actual PVC mount"
    )
    assert ".Values.persistence.mountPath" in mount_expr, (
        f"volumeMounts.mountPath {mount_expr!r} is not templated off "
        "persistence.mountPath"
    )


def test_readonly_root_filesystem_makes_the_env_var_mandatory():
    """Sanity-check the premise: the security posture that makes an unset
    NEXUS_VAULT_DIR fatal (readOnlyRootFilesystem) is actually enabled, so
    this test suite is guarding a real, currently-active failure mode."""
    values = yaml.safe_load(VALUES_FILE.read_text(encoding="utf-8"))
    assert values["securityContext"]["readOnlyRootFilesystem"] is True
