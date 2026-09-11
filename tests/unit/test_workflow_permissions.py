"""Regression test: GitHub Actions workflow permissions must not grant
scopes the workflow has no step to use.

`security-events: write` widens the GITHUB_TOKEN's blast radius (write
access to the repo's Security tab) for every run of the triggering event
(including `pull_request` from any contributor, since the workflow uses
the read-privileged `pull_request` trigger rather than
`pull_request_target`). That permission is only justified when a step
actually uploads SARIF or otherwise calls the code-scanning API (e.g. via
`github/codeql-action/upload-sarif` or a raw call to the
`code-scanning/sarifs` REST endpoint). If no step does that, the grant is
unused and should be removed (or the scope narrowed to `write` only on the
job that needs it, with a step that uses it).
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def _load_workflow(name: str) -> dict:
    path = WORKFLOWS_DIR / name
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _uses_code_scanning_api(workflow: dict) -> bool:
    """True if any step in the workflow uploads SARIF / hits the
    code-scanning API — the only legitimate consumer of
    `security-events: write`."""
    haystacks: list[str] = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            uses = step.get("uses") or ""
            run = step.get("run") or ""
            haystacks.append(uses)
            haystacks.append(run)
    blob = "\n".join(haystacks).lower()
    return (
        "upload-sarif" in blob
        or "code-scanning/sarifs" in blob
        or "codeql-action" in blob
    )


def _collect_permission_grants(workflow: dict) -> dict[str, str]:
    """Merge top-level and per-job `permissions:` blocks into one dict of
    scope -> level, mirroring how GitHub Actions resolves permissions
    (job-level overrides workflow-level, but for this check we only care
    about scopes that are granted *anywhere* in the file)."""
    grants: dict[str, str] = {}
    top = workflow.get("permissions")
    if isinstance(top, dict):
        grants.update(top)
    for job in (workflow.get("jobs") or {}).values():
        job_perms = job.get("permissions")
        if isinstance(job_perms, dict):
            grants.update(job_perms)
    return grants


def test_security_workflow_does_not_grant_unused_security_events_write():
    """security.yml has no step that uploads SARIF or calls the
    code-scanning API, so it must not carry `security-events: write` —
    that permission would otherwise grant every run (including
    `pull_request` from any contributor) write access to the repo's
    Security tab for no functional reason."""
    workflow = _load_workflow("security.yml")
    grants = _collect_permission_grants(workflow)

    assert not _uses_code_scanning_api(workflow), (
        "security.yml now uploads SARIF/uses the code-scanning API — if you "
        "added that intentionally, also (re-)grant `security-events: write` "
        "and update/remove this test rather than deleting it."
    )
    assert grants.get("security-events") != "write", (
        "security.yml grants `security-events: write` but no step uploads "
        "SARIF or calls the code-scanning API — remove the unused, "
        "overly-broad permission."
    )


def test_no_workflow_grants_security_events_write_without_using_it():
    """General guard for every workflow file: `security-events: write` is
    only legitimate alongside a step that actually uses it."""
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        workflow = _load_workflow(path.name)
        grants = _collect_permission_grants(workflow)
        if grants.get("security-events") == "write":
            assert _uses_code_scanning_api(workflow), (
                f"{path.name} grants `security-events: write` but has no "
                "step that uploads SARIF or calls the code-scanning API."
            )


def _all_run_commands(workflow: dict) -> list[str]:
    commands: list[str] = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run")
            if run:
                commands.append(run)
    return commands


def test_security_workflow_does_not_duplicate_ci_ruff_step():
    """security.yml must not re-run ci.yml's `ruff check` step.

    That ruff invocation (`--select E9,F63,F7,F82`) only catches syntax
    errors and undefined names — it is not a security-specific lint, and
    ci.yml already runs it on every push/PR. Duplicating it inside a job
    named "Security Hardening" wastes CI minutes and misleads a reviewer
    into thinking extra security static analysis is happening beyond what
    Bandit (and pip-audit/Trivy) already provide below it.
    """
    ci = _load_workflow("ci.yml")
    security = _load_workflow("security.yml")

    ci_ruff_commands = [
        cmd for cmd in _all_run_commands(ci) if "ruff check" in cmd
    ]
    security_ruff_commands = [
        cmd for cmd in _all_run_commands(security) if "ruff check" in cmd
    ]

    assert ci_ruff_commands, (
        "expected ci.yml to still run `ruff check` — if it no longer does, "
        "update this test rather than deleting it."
    )
    assert not security_ruff_commands, (
        "security.yml re-runs `ruff check` (already covered by ci.yml on "
        "every push/PR) — remove the duplicate step instead of "
        f"reintroducing it. Found: {security_ruff_commands!r}"
    )


def _bandit_commands(workflow: dict) -> list[str]:
    return [cmd for cmd in _all_run_commands(workflow) if "bandit " in f" {cmd} "]


def test_security_workflow_bandit_step_gates_on_high_severity_only():
    """security.yml's Bandit step must filter to HIGH severity (`-lll`),
    mirroring ci.yml's deliberate HIGH-only blocking gate.

    Unfiltered `bandit -q -r nexus -x tests` exits non-zero on this repo's
    147 pre-existing LOW/MEDIUM findings (verified: 129 LOW/high-confidence,
    9 LOW/medium-confidence, 9 MEDIUM/medium-confidence — e.g. B104
    hardcoded_bind_all_interfaces, B108 hardcoded_tmp_directory, B110
    try_except_pass) even though zero HIGH-severity issues exist. That
    makes the job fail on every push/PR/cron run regardless of real risk,
    per docs/production_readiness.md's own triage baseline.
    """
    security = _load_workflow("security.yml")
    bandit_commands = _bandit_commands(security)

    assert bandit_commands, (
        "expected security.yml to still run Bandit — if it no longer does, "
        "update this test rather than deleting it."
    )
    for cmd in bandit_commands:
        # A line invoking bandit with no severity flag (`-l`/`-ll`/`-lll`)
        # and no `||` fallback actually gates the job on its exit code —
        # that's the bug, since unfiltered Bandit exits 1 on this repo's
        # advisory-only LOW/MEDIUM noise. A line with a `||` fallback (like
        # the advisory "full report" line below) never fails the job, so it
        # is fine to run unfiltered.
        blocking_lines = [
            line
            for line in cmd.splitlines()
            if "bandit " in f" {line} " and "-l" not in line and "||" not in line
        ]
        assert not blocking_lines, (
            "security.yml runs Bandit without a severity filter and "
            "without an `||` fallback, so it fails the job on pre-existing "
            f"LOW/MEDIUM findings instead of only HIGH: {blocking_lines!r}"
        )

    combined = "\n".join(bandit_commands)
    assert "-lll" in combined, (
        "security.yml's Bandit step should gate blocking on HIGH severity "
        "only (`-lll`), same as ci.yml, with MEDIUM/LOW left advisory."
    )


def test_security_workflow_pip_audit_scans_the_same_lock_file_as_ci():
    """security.yml's pip-audit step must scan requirements.lock.txt, the
    same pinned file ci.yml audits and the one the Docker image actually
    installs from. A bare `pip-audit` with no `-r` instead introspects
    whatever happens to be installed via `pip install -e ".[dev]"` in this
    job, which can silently diverge from the lock file (a stale lock, or
    dev-only extras absent from the shipped image) and report a different
    vulnerable-package set than ci.yml's own audit of the same dependency
    tree.
    """
    ci = _load_workflow("ci.yml")
    security = _load_workflow("security.yml")

    ci_pip_audit = [cmd for cmd in _all_run_commands(ci) if "pip-audit" in cmd]
    security_pip_audit = [cmd for cmd in _all_run_commands(security) if "pip-audit" in cmd]

    assert ci_pip_audit and security_pip_audit, (
        "expected both workflows to still run pip-audit — if one no longer "
        "does, update this test rather than deleting it."
    )
    assert any("-r requirements.lock.txt" in cmd for cmd in ci_pip_audit)
    assert any("-r requirements.lock.txt" in cmd for cmd in security_pip_audit), (
        "security.yml's pip-audit step should scan requirements.lock.txt "
        "explicitly (`-r requirements.lock.txt`), matching ci.yml, instead "
        "of a bare `pip-audit` that scans whatever's installed in the job "
        "environment."
    )
