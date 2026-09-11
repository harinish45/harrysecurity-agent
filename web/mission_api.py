"""Mission-control HTTP adapter for the local dashboard."""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from nexus.foundation.guardrails import InputGuard, LegalGuard, ScopeGuard
from nexus.mission import MissionStatus, MissionStore, MissionService

router = APIRouter(prefix="/api/missions", tags=["missions"])
_service = MissionService(MissionStore(os.environ.get("NEXUS_MISSIONS_DIR", "engagements/missions")))

# Bounds enforced on create_mission's free-text fields before persisting to
# engagements/missions/ — previously bare str()-coerced with no length
# limit, so a client could grow a mission file (and the metadata dict
# specifically) without bound, a real disk-exhaustion DoS via this route.
_MAX_FIELD_LEN = 500
_MAX_METADATA_BYTES = 8192


def _require_token(request: Request) -> None:
    """Delegates to web/server.py's real auth check instead of maintaining
    a second, independent implementation here.

    This used to be its own, weaker check: a plain (non-constant-time)
    string `!=` against the shared DASHBOARD_TOKEN only, with no
    integration at all with nexus.foundation.auth's per-user sessions —
    an authenticated per-user session that works on every other /api/*
    route in web/server.py got a flat 401 here, and (the more serious
    direction) the shared token granted full create/transition/replay
    access with none of the fine-grained Permission checks
    (SCAN_CREATE/CONFIG_WRITE/etc.) this session added elsewhere. Deferred
    import — web/server.py imports this module's `router` at load time, so
    importing back from web.server at module scope here would be circular;
    resolving it lazily inside the function call avoids that.
    """
    from web.server import _require_token as _server_require_token

    _server_require_token(request)


def _require_mission_permission(request: Request, permission) -> None:
    from web.server import _require_permission as _server_require_permission

    _server_require_permission(request, permission)


def _bounded_str(value: Any, *, default: str = "", field_name: str = "field") -> str:
    text = str(value) if value is not None else default
    if len(text) > _MAX_FIELD_LEN:
        raise HTTPException(status_code=400, detail=f"{field_name} exceeds {_MAX_FIELD_LEN} characters")
    return text


def _bounded_metadata(value: Any) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="metadata must be an object")
    import json

    try:
        size = len(json.dumps(value))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"metadata is not JSON-serializable: {exc}") from exc
    if size > _MAX_METADATA_BYTES:
        raise HTTPException(status_code=400, detail=f"metadata exceeds {_MAX_METADATA_BYTES} bytes")
    return value


def _validate_target(target: Any) -> str:
    if not isinstance(target, str) or not target.strip():
        raise HTTPException(status_code=400, detail="target must be a non-empty string")
    if len(target) > _MAX_FIELD_LEN:
        raise HTTPException(status_code=400, detail=f"target exceeds {_MAX_FIELD_LEN} characters")
    try:
        InputGuard.validate(target, context={"source": "mission-api"})
        ScopeGuard.validate(target)
        LegalGuard.validate(target=target)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Mission blocked by guardrail: {exc}") from exc
    return target.strip()


@router.post("")
async def create_mission(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    from web.middleware import require_same_origin_signal
    from nexus.foundation.auth import Permission

    _require_token(request)
    require_same_origin_signal(request)
    _require_mission_permission(request, Permission.SCAN_CREATE)
    target = _validate_target(payload.get("target"))
    mode = _bounded_str(payload.get("mode"), default="guided", field_name="mode")
    objective = _bounded_str(payload.get("objective"), default="full_assessment", field_name="objective")
    workflow = _bounded_str(payload.get("workflow"), default="full_assessment", field_name="workflow")
    authorization_reference = _bounded_str(
        payload.get("authorization_reference"), default="", field_name="authorization_reference"
    )
    mission = _service.create(
        target,
        mode=mode,
        objective=objective,
        workflow=workflow,
        authorization_reference=authorization_reference,
        metadata=_bounded_metadata(payload.get("metadata")),
    )
    return _service.summarize(mission).to_dict()


@router.get("")
async def list_missions(request: Request) -> dict[str, Any]:
    from nexus.foundation.auth import Permission

    _require_token(request)
    _require_mission_permission(request, Permission.REPORT_READ)
    items = _service.list()
    return {"missions": [item.to_dict() for item in items], "total": len(items)}


@router.get("/{mission_id}")
async def get_mission(mission_id: str, request: Request) -> dict[str, Any]:
    from nexus.foundation.auth import Permission

    _require_token(request)
    _require_mission_permission(request, Permission.REPORT_READ)
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
    from web.middleware import require_same_origin_signal
    from nexus.foundation.auth import Permission

    _require_token(request)
    require_same_origin_signal(request)
    _require_mission_permission(request, Permission.SCAN_CREATE)
    try:
        status = MissionStatus(str(payload.get("status", "")))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid mission status") from None
    try:
        mission = _service.transition(
            mission_id,
            status,
            actor=_bounded_str(payload.get("actor"), default="dashboard", field_name="actor"),
            reason=_bounded_str(payload.get("reason"), default="", field_name="reason"),
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Mission not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _service.summarize(mission).to_dict()


@router.get("/{mission_id}/events")
async def replay_events(mission_id: str, request: Request, after_sequence: int = 0) -> dict[str, Any]:
    from nexus.foundation.auth import Permission

    _require_token(request)
    _require_mission_permission(request, Permission.REPORT_READ)
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
