"""Dead Letter Queue helpers for Redis Streams workers.

Retry / DLQ flow
----------------
1. First failure  → do NOT xack → message stays in PEL (Pending Entry List).
2. Each worker's main loop calls ``reclaim_pending`` periodically.
   ``XAUTOCLAIM`` picks up messages that have been idle > dlq_idle_seconds.
3. On each reclaim attempt the retry counter is incremented.
4. Once the counter reaches dlq_max_retries the message is written to the
   dead-letter stream and xack-ed so it no longer blocks the PEL.

The retry counter is stored as a plain Redis key with a 24-hour TTL so it
survives container restarts but cleans itself up automatically.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable

from redis.asyncio import Redis

from app.common.logging import get_logger
from app.redis_kv import streams

log = get_logger(__name__)

_RETRY_TTL_SECONDS = 86_400   # 24 h — auto-expire stale counters
_DLQ_MAXLEN = 10_000


# ---------------------------------------------------------------------------
# Retry counter helpers
# ---------------------------------------------------------------------------

def _retry_key(stream_id: str) -> str:
    # stream_id looks like "1699000000000-0" — safe as a Redis key
    return f"dlq:retry:{stream_id}"


async def get_retry_count(redis: Redis, stream_id: str) -> int:
    val = await redis.get(_retry_key(stream_id))
    return int(val) if val else 0


async def increment_retry(redis: Redis, stream_id: str) -> int:
    key = _retry_key(stream_id)
    count = await redis.incr(key)
    await redis.expire(key, _RETRY_TTL_SECONDS)
    return int(count)


async def clear_retry(redis: Redis, stream_id: str) -> None:
    await redis.delete(_retry_key(stream_id))


# ---------------------------------------------------------------------------
# DLQ writer
# ---------------------------------------------------------------------------

async def push_to_dlq(
    redis: Redis,
    tenant_id: str,
    stage: str,
    stream_id: str,
    payload: str,
    error: Exception | str,
) -> None:
    """Write a failed message to the dead-letter stream and clear its counter."""
    await redis.xadd(
        streams.events_deadletter(tenant_id),
        {
            "stage": stage,
            "stream_id": stream_id,
            "payload": payload[:4096],
            "error": str(error)[:1000],
            "failed_at": datetime.now(timezone.utc).isoformat(),
        },
        maxlen=_DLQ_MAXLEN,
        approximate=True,
    )
    await clear_retry(redis, stream_id)
    log.warning(
        "message_sent_to_dlq",
        stage=stage,
        stream_id=stream_id,
        error=str(error)[:200],
    )


# ---------------------------------------------------------------------------
# PEL reclaimer
# ---------------------------------------------------------------------------

async def reclaim_pending(
    redis: Redis,
    stream: str,
    group: str,
    consumer: str,
    tenant_id: str,
    stage: str,
    idle_ms: int,
    max_retries: int,
    handler: Callable[[str, dict], Awaitable[None]],
) -> None:
    """Claim idle PEL entries and retry them, moving to DLQ after max_retries.

    Parameters
    ----------
    handler:
        Async callable ``(stream_id, fields) -> None`` that processes one
        message.  Should raise on failure so we can track the retry count.
    """
    try:
        next_id, claimed, _ = await redis.xautoclaim(
            stream,
            group,
            consumer,
            min_idle_time=idle_ms,
            start_id="0-0",
            count=10,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("xautoclaim_failed", stream=stream, error=str(exc))
        return

    if not claimed:
        return

    for stream_id, fields in claimed:
        sid = stream_id.decode() if isinstance(stream_id, bytes) else str(stream_id)
        raw_fields = {
            (k.decode() if isinstance(k, bytes) else k): (
                v.decode() if isinstance(v, bytes) else v
            )
            for k, v in fields.items()
        }
        try:
            await handler(sid, raw_fields)
            await redis.xack(stream, group, sid)
            await clear_retry(redis, sid)
            log.info("pending_message_recovered", stream_id=sid)
        except Exception as exc:  # noqa: BLE001
            count = await increment_retry(redis, sid)
            if count >= max_retries:
                payload = raw_fields.get("payload") or raw_fields.get("signal") or ""
                await push_to_dlq(redis, tenant_id, stage, sid, payload, exc)
                await redis.xack(stream, group, sid)
            else:
                log.warning(
                    "pending_message_retry_scheduled",
                    stream_id=sid,
                    attempt=count,
                    max=max_retries,
                    error=str(exc)[:200],
                )
