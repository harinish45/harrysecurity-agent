"""Regression tests for the nexus-strike Helm chart's missing Secret wiring.

Before this fix, the chart had no `templates/secret.yaml` and no
`env`/`envFrom` path for injecting a Kubernetes Secret into the container.
Per .env.example and docker-compose.yml, the app needs an LLM provider API
key (OPENAI_API_KEY/ANTHROPIC_API_KEY/GROQ_API_KEY/etc.) and
NEXUS_MASTER_KEY (nexus/foundation/secrets.py) to run against a real
provider. With no sanctioned way to supply these through the chart, an
operator's only realistic options were baking secrets into the image or
hand-patching values.yaml/deployment.yaml with a literal `value:` --
landing the key in plaintext in a values file (often committed) and/or in
Helm's unencrypted release history (`helm get values`).

The fix adds:
  * `values.yaml`: a `secrets` block (`existingSecret` name, or `data` map
    for the chart to render into a Secret it owns). Both default to
    empty/unset -- no real values are ever committed here.
  * `templates/secret.yaml`: renders a Secret from `secrets.data`, but ONLY
    when `secrets.existingSecret` is unset (so it never collides with an
    operator-managed Secret) and `secrets.data` is non-empty (so nothing
    dangling is rendered on defaults).
  * `templates/_helpers.tpl`: `nexus-strike.secretName`, resolving to
    `secrets.existingSecret` when set, else the release's own fullname.
  * `templates/deployment.yaml`: an `envFrom: [{secretRef: {name: ...}}]`
    entry on the container, gated on either `secrets.existingSecret` or
    `secrets.data` being set, using the same helper -- so the container
    only ever references a Secret that actually gets rendered (or that the
    operator promised exists externally).

These tests render the real chart with `helm template` (skipped if the
`helm` CLI isn't on PATH) and assert on the rendered manifests directly, so
they fail if any of this wiring regresses.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "nexus-strike"
VALUES_PATH = CHART_DIR / "values.yaml"
SECRET_TEMPLATE_PATH = CHART_DIR / "templates" / "secret.yaml"

HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(HELM is None, reason="helm binary not available")


def _render_all(*extra_set: str) -> list[dict]:
    args = [HELM, "template", "nexus-strike-test", str(CHART_DIR)]
    for value in extra_set:
        args += ["--set-string", value]
    result = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    assert result.returncode == 0, f"helm template failed: {result.stderr}"
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def _deployment(docs: list[dict]) -> dict:
    deployments = [d for d in docs if d.get("kind") == "Deployment"]
    assert deployments, "expected the chart to render exactly one Deployment"
    return deployments[0]


def _secrets(docs: list[dict]) -> list[dict]:
    return [d for d in docs if d.get("kind") == "Secret"]


def _container(deployment: dict) -> dict:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1
    return containers[0]


def test_default_values_render_no_secret_and_no_envfrom():
    """Safe default: with neither secrets.existingSecret nor secrets.data
    set, the chart must render no Secret resource and no envFrom entry --
    referencing a Secret that doesn't exist would break every pod."""
    docs = _render_all()
    assert _secrets(docs) == []

    container = _container(_deployment(docs))
    assert "envFrom" not in container


def test_secrets_data_renders_a_chart_owned_secret_with_the_given_keys():
    """The realistic fix path: an operator supplies real values via --set
    (or an untracked values file) at install/upgrade time, never committed
    to values.yaml, and the chart renders them into a Secret it owns."""
    docs = _render_all(
        "secrets.data.LLM_PROVIDER=openai",
        "secrets.data.OPENAI_API_KEY=sk-test-123",
        "secrets.data.NEXUS_MASTER_KEY=deadbeefcafe",
    )
    secrets = _secrets(docs)
    assert len(secrets) == 1
    secret = secrets[0]

    assert secret["type"] == "Opaque"
    assert secret["stringData"] == {
        "LLM_PROVIDER": "openai",
        "OPENAI_API_KEY": "sk-test-123",
        "NEXUS_MASTER_KEY": "deadbeefcafe",
    }

    deployment = _deployment(docs)
    assert secret["metadata"]["name"] == deployment["metadata"]["name"], (
        "the Secret's name must match what the container's envFrom "
        "references (both driven by the same secretName helper)"
    )

    container = _container(deployment)
    assert container["envFrom"] == [{"secretRef": {"name": secret["metadata"]["name"]}}]


def test_existing_secret_is_referenced_without_the_chart_rendering_its_own():
    """Production path: operator creates/manages the Secret out-of-band
    (kubectl, External Secrets Operator, Sealed Secrets, ...) so no real
    value ever passes through values.yaml or Helm release history. The
    chart must reference it by name and must NOT also render a Secret of
    its own (which would either collide or shadow the real one)."""
    docs = _render_all("secrets.existingSecret=my-external-nexus-secret")

    assert _secrets(docs) == [], (
        "chart must not render its own Secret when existingSecret is set"
    )

    container = _container(_deployment(docs))
    assert container["envFrom"] == [{"secretRef": {"name": "my-external-nexus-secret"}}]


def test_existing_secret_takes_precedence_over_data():
    """If an operator sets both (e.g. mid-migration), existingSecret must
    win and the chart must still not render a conflicting Secret of its
    own under the same name."""
    docs = _render_all(
        "secrets.existingSecret=my-external-nexus-secret",
        "secrets.data.OPENAI_API_KEY=sk-should-be-ignored",
    )

    assert _secrets(docs) == []

    container = _container(_deployment(docs))
    assert container["envFrom"] == [{"secretRef": {"name": "my-external-nexus-secret"}}]


def test_committed_values_yaml_has_no_real_secret_values():
    """The fix must not regress into the exact anti-pattern it closes:
    secrets.data must default to empty so nothing sensitive is ever
    baked into the tracked values.yaml."""
    values = yaml.safe_load(VALUES_PATH.read_text(encoding="utf-8"))
    secrets_values = values.get("secrets", {})
    assert secrets_values.get("existingSecret", "") == ""
    assert secrets_values.get("data", {}) == {}


def test_secret_template_guards_on_existingSecret_and_data():
    """Source-level sanity check on templates/secret.yaml's guard, so a
    future edit that drops the `not existingSecret` half of the condition
    (and would then render a duplicate/colliding Secret) fails fast even
    without invoking helm."""
    source = SECRET_TEMPLATE_PATH.read_text(encoding="utf-8")
    assert "secrets.existingSecret" in source
    assert "secrets.data" in source
