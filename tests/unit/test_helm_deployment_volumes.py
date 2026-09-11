"""Regression test for a real gap in the Helm chart's pod spec:

deploy/helm/nexus-strike/templates/deployment.yaml declared exactly one
volumeMount -- the vault PVC at .Values.persistence.mountPath -- while
Dockerfile:72 creates (and the app writes to at runtime) three more
directories: /app/reports, /app/engagements and /app/logs, plus /tmp for
general scratch/temp files. docker-compose.yml bind-mounts all four of
those paths (and gives /tmp a tmpfs) for exactly this reason. With
securityContext.readOnlyRootFilesystem: true (values.yaml) and no volume
backing those paths in the Helm chart, any write to them (a generated
pentest report, engagement state, or the nexus_audit.log audit trail)
raised "OSError: Read-only file system" -- silent loss of the very
evidence/compliance artifacts this tool exists to produce.

The chart's templates use Go template directives ({{ ... }}), so they are
not valid standalone YAML and can't be round-tripped through yaml.safe_load
without a running `helm template` (not available in this environment).
These tests instead assert directly on the source template/values, which is
what actually controls the generated manifest.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

CHART_DIR = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "nexus-strike"
DEPLOYMENT_TEMPLATE = CHART_DIR / "templates" / "deployment.yaml"
VALUES_FILE = CHART_DIR / "values.yaml"

# Paths Dockerfile:72 creates specifically so the app can write engagement
# data, generated reports, and the audit log while running as a non-root
# user -- plus /tmp, which every process needs regardless.
REQUIRED_WRITABLE_PATHS = {
    "/tmp",
    "/app/reports",
    "/app/engagements",
    "/app/logs",
}


def _deployment_source() -> str:
    return DEPLOYMENT_TEMPLATE.read_text(encoding="utf-8")


def _values() -> dict:
    return yaml.safe_load(VALUES_FILE.read_text(encoding="utf-8"))


def _volume_mounts_block(source: str) -> str:
    match = re.search(r"volumeMounts:\n(?P<body>.*?)\n {6}volumes:\n", source, re.DOTALL)
    assert match, "could not isolate the volumeMounts: block in deployment.yaml"
    return match.group("body")


def _volumes_block(source: str) -> str:
    match = re.search(r"\n {6}volumes:\n(?P<body>.*)\Z", source, re.DOTALL)
    assert match, "could not isolate the volumes: block in deployment.yaml"
    return match.group("body")


def _mount_entries(volume_mounts_block: str) -> dict[str, str]:
    """{volume name: mountPath expression (verbatim, template exprs included
    in full rather than truncated at the first space)} for every
    - name:/mountPath: pair."""
    return {
        name: path.strip()
        for name, path in re.findall(
            r"-\s*name:\s*(\S+)\s*\n\s*mountPath:\s*(.+)",
            volume_mounts_block,
        )
    }


def _volume_names(volumes_block: str) -> set[str]:
    return set(re.findall(r"-\s*name:\s*(\S+)", volumes_block))


def test_readonly_root_filesystem_makes_extra_volumes_mandatory():
    """Sanity-check the premise: the security posture that makes an
    unmounted writable path fatal (readOnlyRootFilesystem) is actually
    enabled, so this test suite is guarding a real, currently-active
    failure mode."""
    values = _values()
    assert values["securityContext"]["readOnlyRootFilesystem"] is True


def test_every_dockerfile_writable_path_has_a_volume_mount():
    """Each path Dockerfile:72 creates for runtime writes (other than the
    vault, which already had its own PVC mount) must be mounted somewhere
    -- the regression was that only nexus-state was mounted at all."""
    mounts = _mount_entries(_volume_mounts_block(_deployment_source()))
    mounted_paths = set(mounts.values())
    missing = REQUIRED_WRITABLE_PATHS - mounted_paths
    assert not missing, (
        f"these paths are created by Dockerfile:72 / written to at runtime "
        f"but have no volumeMount under readOnlyRootFilesystem: {missing}"
    )


def test_every_volume_mount_has_a_matching_volume_definition():
    """A volumeMount with no corresponding entry in `volumes:` is a
    dangling reference that fails the whole Deployment at apply time --
    guard against the fix adding a mount but forgetting the volume (or
    vice versa)."""
    source = _deployment_source()
    mount_names = set(_mount_entries(_volume_mounts_block(source)).keys())
    volume_names = _volume_names(_volumes_block(source))
    assert mount_names == volume_names, (
        f"volumeMounts names {mount_names} and volumes names {volume_names} "
        "must match exactly"
    )


def test_new_writable_paths_use_emptydir_not_left_unbacked():
    """Each of the newly-mounted paths must actually declare a volume
    source (emptyDir), not just a bare `- name:` entry with nothing
    backing it (which Kubernetes would reject)."""
    volumes_block = _volumes_block(_deployment_source())
    for name in ("tmp", "reports", "engagements", "logs"):
        entry_match = re.search(
            rf"-\s*name:\s*{name}\s*\n(?P<body>(?:\s+\S.*\n?)*)",
            volumes_block,
        )
        assert entry_match, f"no volumes entry named {name!r} found"
        assert "emptyDir:" in entry_match.group("body"), (
            f"volumes entry {name!r} does not declare an emptyDir source"
        )


def test_emptydir_sizelimits_are_configurable_via_values():
    """The emptyDir sizeLimits must be driven by values.yaml (not hardcoded
    in the template), and values.yaml must actually define them."""
    source = _deployment_source()
    volumes_block = _volumes_block(source)
    for name in ("tmp", "reports", "engagements", "logs"):
        assert f".Values.emptyDirs.{name}.sizeLimit" in volumes_block, (
            f"emptyDir for {name!r} should be templated off "
            f".Values.emptyDirs.{name}.sizeLimit"
        )

    values = _values()
    empty_dirs = values.get("emptyDirs", {})
    for name in ("tmp", "reports", "engagements", "logs"):
        assert name in empty_dirs and empty_dirs[name].get("sizeLimit"), (
            f"values.yaml must define emptyDirs.{name}.sizeLimit"
        )


def test_vault_pvc_mount_untouched_by_the_fix():
    """The pre-existing vault PVC mount (the one mount that already worked)
    must still be present and still backed by the PVC, not accidentally
    replaced or duplicated while adding the new volumes."""
    source = _deployment_source()
    mounts = _mount_entries(_volume_mounts_block(source))
    assert "nexus-state" in mounts
    assert ".Values.persistence.mountPath" in mounts["nexus-state"]

    volumes_block = _volumes_block(source)
    nexus_state_match = re.search(
        r"-\s*name:\s*nexus-state\s*\n(?P<body>(?:\s+\S.*\n?)*)",
        volumes_block,
    )
    assert nexus_state_match, "nexus-state volume definition missing"
    assert "persistentVolumeClaim:" in nexus_state_match.group("body")
