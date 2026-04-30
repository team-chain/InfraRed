"""FastAPI routes owned by role A."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError

from app.config import get_settings
from app.db.repositories import touch_heartbeat
from app.iam.security import verify_agent_token
from app.models.dead_letter import DeadLetter
from app.models.envelope import RawEventEnvelope
from app.models.heartbeat import Heartbeat
from app.redis_kv import streams
from app.redis_kv.client import get_redis


router = APIRouter()


async def _write_deadletter(tenant_id: str, reason: str, message: str, payload: str) -> None:
    redis = get_redis()
    item = DeadLetter(
        event_id="unknown",
        reason=reason,
        error_message=message,
        failed_at=datetime.now(timezone.utc),
        raw_payload=payload[:4096],
    )
    await redis.xadd(
        streams.events_deadletter(tenant_id),
        {"payload": item.model_dump_json()},
        maxlen=get_settings().redis_stream_maxlen,
        approximate=True,
    )


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    request: Request,
    claims: dict = Depends(verify_agent_token),
) -> dict[str, str | bool]:
    settings = get_settings()
    body = await request.body()
    if len(body) > settings.payload_max_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    try:
        payload = json.loads(body)
        envelope = RawEventEnvelope.model_validate(payload)
    except (json.JSONDecodeError, ValidationError) as exc:
        tenant_id = claims.get("tenant_id", settings.tenant_id)
        await _write_deadletter(tenant_id, "schema_validation_failed", str(exc), body.decode())
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="bad_envelope")

    if claims.get("tenant_id") != envelope.tenant_id:
        await _write_deadletter(
            claims.get("tenant_id", settings.tenant_id),
            "tenant_mismatch",
            "token tenant does not match envelope tenant",
            body.decode(),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_mismatch")
    if claims.get("agent_id") and claims.get("agent_id") != envelope.agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent_mismatch")

    age = datetime.now(timezone.utc) - envelope.timestamp.astimezone(timezone.utc)
    if age.total_seconds() > settings.late_event_max_seconds:
        await _write_deadletter(
            envelope.tenant_id,
            "event_too_old",
            "event timestamp exceeded late_event_max_seconds",
            body.decode(),
        )
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="event_too_old")
    envelope.late_event = age.total_seconds() > settings.late_event_threshold_seconds

    redis = get_redis()
    stream_id = await redis.xadd(
        streams.events_raw(envelope.tenant_id),
        {"payload": envelope.model_dump_json()},
        maxlen=settings.redis_stream_maxlen,
        approximate=True,
    )
    return {"accepted": True, "stream_id": stream_id, "event_id": envelope.event_id}


@router.post("/heartbeat", status_code=status.HTTP_202_ACCEPTED)
async def heartbeat(
    heartbeat_event: Heartbeat,
    claims: dict = Depends(verify_agent_token),
) -> dict[str, bool]:
    if claims.get("tenant_id") != heartbeat_event.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_mismatch")
    if claims.get("agent_id") and claims.get("agent_id") != heartbeat_event.agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent_mismatch")
    await touch_heartbeat(heartbeat_event)
    return {"accepted": True}
