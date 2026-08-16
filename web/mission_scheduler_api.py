"""Mission-to-scheduler control-plane adapter.

This layer creates authorized WorkerJob records; execution remains the worker
fabric's responsibility. It never constructs shell commands from user input.
"""
from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from nexus.agents.capabilities import RiskLevel
from nexus.foundation.guardrails import InputGuard, LegalGuard, ScopeGuard
from nexus.runtime.scheduler import JobScheduler
from nexus.runtime.workers import WorkerJob
from web.mission_api import _require_token, _service

router = APIRouter(prefix="/api/missions", tags=["mission-jobs"])
_scheduler = JobScheduler()


@router.post("/{mission_id}/jobs")
async def submit_job(mission_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
    _require_token(request)
    try:
        mission = _service.get(mission_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Mission not found") from None

    if mission.status.value not in {"authorized", "planning", "queued", "running", "paused"}:
        raise HTTPException(status_code=409, detail=f"Mission state {mission.status.value} cannot accept jobs")

    target_scope = payload.get("target_scope")
    if not isinstance(target_scope, list) or not target_scope or not all(isinstance(item, str) for item in target_scope):
        raise HTTPException(status_code=400, detail="target_scope must be a non-empty string list")

    try:
        for target in target_scope:
            InputGuard.validate(target, context={"source": "mission-job"})
            ScopeGuard.validate(target)
            LegalGuard.validate(target=target)
        if mission.target not in target_scope and not any(target == mission.target for target in target_scope):
            raise ValueError("job scope must include the mission target")
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Job blocked by guardrail: {exc}") from exc

    capability = str(payload.get("capability", "")).strip()
    if not capability:
        raise HTTPException(status_code=400, detail="capability is required")
    try:
        risk = RiskLevel(str(payload.get("risk_level", "low")))
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid risk_level") from None

    job = WorkerJob(
        job_id=str(payload.get("job_id") or f"job_{uuid4().hex}"),
        mission_id=mission_id,
        task_id=str(payload.get("task_id") or f"task_{uuid4().hex}"),
        capability=capability,
        target_scope=tuple(target_scope),
        risk_level=risk,
        timeout_seconds=int(payload.get("timeout_seconds", 300)),
    )
    try:
        scheduled = _scheduler.submit(job, priority=int(payload.get("priority", 100)))
        _service.record(
            mission_id,
            "job.queued",
            actor="mission-api",
            payload={"job_id": job.job_id, "capability": job.capability, "risk_level": job.risk_level.value},
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return {
        "job_id": scheduled.job.job_id,
        "mission_id": scheduled.job.mission_id,
        "task_id": scheduled.job.task_id,
        "capability": scheduled.job.capability,
        "state": scheduled.state.value,
        "priority": scheduled.priority,
        "target_scope": list(scheduled.job.target_scope),
    }


@router.get("/{mission_id}/jobs")
async def list_jobs(mission_id: str, request: Request) -> dict[str, Any]:
    _require_token(request)
    try:
        _service.get(mission_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Mission not found") from None
    items = _scheduler.list(mission_id)
    return {
        "mission_id": mission_id,
        "jobs": [
            {
                "job_id": item.job.job_id,
                "task_id": item.job.task_id,
                "capability": item.job.capability,
                "state": item.state.value,
                "priority": item.priority,
                "attempt": item.job.attempt,
                "retries": item.retries,
                "error": item.error,
                "target_scope": list(item.job.target_scope),
            }
            for item in items
        ],
    }
