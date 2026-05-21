"""Direct API ingestion endpoint.

Customers POST structured events from their own backend:

  POST /ingest/event
  Authorization: Bearer <API_KEY>       ← also accepted via X-Tenant-Token
  Content-Type: application/json

  {
    "event_type": "ssh_login_failed",   # or any EventType value
    "source_ip":  "1.2.3.4",
    "username":   "root",
    "timestamp":  "2026-05-09T03:12:01Z",
    "host":       "web-01",

    # web event optional fields
    "request_path":   "/admin",
    "request_method": "GET",
    "status_code":    403,
    "user_agent":     "curl/7.88"
  }

Batch endpoint (up to 200 events):

  POST /ingest/events
  [ {...}, {...}, ... ]
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.config import get_settings
from app.iam.api_key import verify_api_key
from app.models.envelope import RawEventEnvelope
from app.redis_kv import streams
from app.redis_kv.client import get_redis

router = APIRouter()


class DirectEvent(BaseModel):
    event_type: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    result: Optional[str] = None
    host: Optional[str] = None
    asset_id: Optional[str] = None
    raw_source: Optional[str] = "api"
    raw_line: Optional[str] = None

    # web fields
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    response_bytes: Optional[int] = None


def _to_envelope(event: DirectEvent, tenant_id: str) -> RawEventEnvelope:
    return RawEventEnvelope(
        event_id=f"api:{uuid.uuid4().hex}",
        tenant_id=tenant_id,
        agent_id=f"direct-api-{tenant_id}",
        timestamp=event.timestamp or datetime.now(timezone.utc),
        event_type=event.event_type,
        raw_source=event.raw_source or "api",
        raw_line=event.raw_line,
        source_ip=event.source_ip,
        username=event.username,
        result=event.result,
        host=event.host,
        asset_id=event.asset_id,
        request_path=event.request_path,
        request_method=event.request_method,
        status_code=event.status_code,
        user_agent=event.user_agent,
        response_bytes=event.response_bytes,
    )


@router.post("/ingest/event", status_code=202)
async def ingest_event_direct(
    event: DirectEvent,
    claims: dict = Depends(verify_api_key),
) -> dict:
    settings = get_settings()
    tenant_id = claims["tenant_id"]
    envelope = _to_envelope(event, tenant_id)

    redis = get_redis()
    stream_id = await redis.xadd(
        streams.events_raw(tenant_id),
        {"payload": envelope.model_dump_json()},
        maxlen=settings.redis_stream_maxlen,
        approximate=True,
    )
    return {"accepted": True, "stream_id": stream_id, "event_id": envelope.event_id}


@router.post("/ingest/events", status_code=202)
async def ingest_events_batch(
    request: Request,
    claims: dict = Depends(verify_api_key),
) -> dict:
    settings = get_settings()
    tenant_id = claims["tenant_id"]

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_json")

    if not isinstance(body, list):
        raise HTTPException(status_code=422, detail="expected_array")

    if len(body) > 200:
        raise HTTPException(status_code=413, detail="batch_too_large_max_200")

    redis = get_redis()
    accepted = 0
    errors = 0
    for raw in body:
        try:
            event = DirectEvent.model_validate(raw)
            envelope = _to_envelope(event, tenant_id)
            await redis.xadd(
                streams.events_raw(tenant_id),
                {"payload": envelope.model_dump_json()},
                maxlen=settings.redis_stream_maxlen,
                approximate=True,
            )
            accepted += 1
        except Exception:
            errors += 1

    return {"accepted": True, "count": accepted, "errors": errors}
