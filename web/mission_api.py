"""Mission-control HTTP adapter for the local dashboard."""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from nexus.foundation.guardrails import InputGuard, LegalGuard, ScopeGuard
from nexus.mission import MissionStatus, MissionStore, MissionService

router = APIRouter(prefix="/api/missions", tags=["missions"])
_service = MissionService(MissionStore(os.environ.get("NEXUS_MISSIONS_DIR", "engagements/missions")))


def _require_token(request: Request) -> None:
    expected = os.environ.get("NEXUS_DASHBOARD_TOKEN", "").strip()
    if expected and request.headers.get("Authorization", "") != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Missing or invalid dashboard token")


def _validate_target(target: Any) -> str:
    if not isinstance(target, str) or not target.strip():
        raise HTTPException(status_code=400, detail="target must be a non-empty string")
    try:
        InputGuard.validate(target, context={"source": "mission-api"})
        ScopeGuard.validate(target)
        LegalGuard.validate(target=target)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Mission blocked by guardrail: {exc}") from exc
    return target.strip()


@router.post("")
async def create_mission(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    _require_token(request)
    target = _validate_target(payload.get("target"))
    mission = _service.create(
        target,
        mode=str(payload.get("mode", "guided")),
        objective=str(payload.get("objective", "full_assessment")),
        workflow=str(payload.get("workflow", "full_assessment")),
        authorization_reference=str(payload.get("authorization_reference", "")),
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )
    return _service.summarize(mission).to_dict()


@router.get("")
async def list_missions(request: Request) -> dict[str, Any]:
    _require_token(request)
    items = _service.list()
    return {"missions": [item.to_dict() for item in items], "total": len(items)}


@router.get("/{mission_id}")
async def get_mission(mission_id: str, request: Request) -> dict[str, Any]:
    _require_token(request)
    try:
        mission = _service.get(mission_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(status_code=404, detail="Mission not found") from None
    return {
        "mission": _service.summarize(mission).to_dict(),
        "event_count": len(mission.events),
    }


@router.post("/{mission_id}/transition")
async def transition_mission(mission_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
    _require_token(request)
    try:
        status = MissionStatus(str(payload.get("status", "")))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid mission status") from None
    try:
        mission = _service.transition(
            mission_id,
            status,
            actor=str(payload.get("actor", "dashboard")),
            reason=str(payload.get("reason", "")),
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Mission not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _service.summarize(mission).to_dict()


@router.get("/{mission_id}/events")
async def replay_events(mission_id: str, request: Request, after_sequence: int = 0) -> dict[str, Any]:
    _require_token(request)
    if after_sequence < 0:
        raise HTTPException(status_code=400, detail="after_sequence must be non-negative")
    try:
        _service.get(mission_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Mission not found") from None
    events = _service.replay(mission_id, after_sequence=after_sequence)
    return {
        "mission_id": mission_id,
        "events": [
            {
                "event_id": event.event_id,
                "mission_id": event.mission_id,
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "payload": event.payload,
                "sequence": event.sequence,
            }
            for event in events
        ],
    }
