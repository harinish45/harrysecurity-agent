"""Non-destructive capability assurance checks.

Assurance validates registry/implementation metadata without executing security
operations. It is safe to run in CI and on developer machines.
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass

from nexus.platform.capabilities import CapabilityState, catalogue
from nexus.platform.workflows import workflows


@dataclass(frozen=True)
class AssuranceResult:
    capability: str
    state: CapabilityState
    healthy: bool
    reason: str


def _module_exists(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def run_assurance() -> list[AssuranceResult]:
    results: list[AssuranceResult] = []
    for spec in catalogue.specs.values():
        if not spec.existing_components:
            results.append(
                AssuranceResult(
                    capability=spec.key,
                    state=CapabilityState.REGISTERED,
                    healthy=True,
                    reason="registered capability; implementation has not been claimed",
                )
            )
            continue
        missing = [component for component in spec.existing_components if not _module_exists(component)]
        results.append(
            AssuranceResult(
                capability=spec.key,
                state=CapabilityState.CALLABLE if not missing else CapabilityState.REGISTERED,
                healthy=not missing,
                reason="all declared components importable" if not missing else f"missing modules: {', '.join(missing)}",
            )
        )
    return sorted(results, key=lambda item: item.capability)


def validate_workflows() -> list[str]:
    """Return task references that do not exist in the canonical capability catalogue."""
    errors: list[str] = []
    for workflow in workflows.list():
        for task in workflow.tasks:
            if catalogue.get(task.capability) is None:
                errors.append(f"{workflow.mode.value}:{task.id}:{task.capability}")
    return errors
