"""SSE (Server-Sent Events) 실시간 Push 엔드포인트 (설계서 6.1).

GET /events/stream — 인증된 사용자에게 실시간 Incident/Demo 이벤트 스트리밍.

백엔드 → 프론트엔드 흐름:
  1. Correlation Worker가 incidents:new 스트림에 이벤트 발행
  2. LLM Worker가 Redis Pub/Sub에 incident_created/updated 이벤트 발행
  3. Detection Worker가 demo_visitor 이벤트 발행 (QR 데모용)
  4. 이 SSE 엔드포인트가 Pub/Sub 구독 → text/event-stream으로 클라이언트에 Push
  5. 프론트엔드 EventSource가 수신 → Incident 목록 자동 갱신
  6. Tray App SSE Worker가 수신 → High/Critical OS 알림 팝업

Redis Pub/Sub 채널: tenant:{tenant_id}:sse
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.common.logging import get_logger
from app.iam.security import verify_user_token
from app.redis_kv.client import get_redis

router = APIRouter(tags=["sse"])
log = get_logger(__name__)

_KEEPALIVE_INTERVAL = 20  # 초 — 연결 유지용 ping


async def _sse_event(event: str, data: dict | str) -> str:
    """SSE wire format 직렬화."""
    if isinstance(data, dict):
        data_str = json.dumps(data, ensure_ascii=False)
    else:
        data_str = str(data)
    return f"event: {event}\ndata: {data_str}\n\n"


async def _sse_generator(tenant_id: str, request: Request):
    """Redis Pub/Sub 구독 → SSE 이벤트 생성기."""
    redis = get_redis()
    pubsub = redis.pubsub()
    channel = f"tenant:{tenant_id}:sse"

    try:
        await pubsub.subscribe(channel)
        log.info("sse_connected", tenant_id=tenant_id)

        # 연결 확인 이벤트
        yield await _sse_event("connected", {"tenant_id": tenant_id, "channel": channel})

        last_keepalive = asyncio.get_event_loop().time()

        while True:
            # 클라이언트 연결 끊김 감지
            if await request.is_disconnected():
                log.info("sse_client_disconnected", tenant_id=tenant_id)
                break

            # Pub/Sub 메시지 수신 (non-blocking)
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                try:
                    payload = json.loads(message["data"])
                    event_type = payload.get("event", "message")
                    data = payload.get("data", payload)
                    yield await _sse_event(event_type, data)
                    log.debug("sse_event_sent", event_type=event_type, tenant_id=tenant_id)
                except Exception as exc:
                    log.warning("sse_parse_failed", error=str(exc))

            # Keepalive ping (연결 유지)
            now = asyncio.get_event_loop().time()
            if now - last_keepalive >= _KEEPALIVE_INTERVAL:
                yield ": ping\n\n"
                last_keepalive = now

    except asyncio.CancelledError:
        log.info("sse_cancelled", tenant_id=tenant_id)
    except Exception as exc:
        log.exception("sse_error", tenant_id=tenant_id, error=str(exc))
    finally:
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
        except Exception:
            pass
        log.info("sse_disconnected", tenant_id=tenant_id)


@router.get("/events/stream")
async def sse_stream(
    request: Request,
    claims: dict = Depends(verify_user_token),
) -> StreamingResponse:
    """GET /events/stream — 실시간 Incident SSE 스트림.

    인증된 사용자에게 tenant별 이벤트 스트리밍.
    프론트엔드: new EventSource('/events/stream', {withCredentials: true})
    Tray App: httpx streaming GET
    """
    tenant_id = claims["tenant_id"]
    return StreamingResponse(
        _sse_generator(tenant_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # nginx 버퍼링 비활성화
            "Connection": "keep-alive",
        },
    )


async def publish_incident_event(
    tenant_id: str,
    event_type: str,
    data: dict,
) -> None:
    """Incident 이벤트를 SSE 채널에 발행 (Correlation Worker, LLM Worker에서 호출).

    event_type 예시: 'incident_created', 'incident_updated', 'llm_completed'
    """
    try:
        redis = get_redis()
        channel = f"tenant:{tenant_id}:sse"
        payload = json.dumps({"event": event_type, "data": data}, ensure_ascii=False)
        await redis.publish(channel, payload)
    except Exception as exc:
        log.warning("sse_publish_failed", event_type=event_type, error=str(exc))
