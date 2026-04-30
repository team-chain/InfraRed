"""Redis 클라이언트 + Key/Stream 패턴 상수.

사용 예:

    from app.redis_kv import keys, streams, get_redis

    r = get_redis()
    await r.xadd(streams.events_raw("company-a"), {"payload": "..."})
    await r.set(keys.event_dedup("company-a", event_id), "1", nx=True, ex=3600)
"""
from __future__ import annotations

import redis.asyncio as redis_async

from app.config import get_settings

from app.redis_kv import keys, streams  # noqa: F401  (재노출)


_client: redis_async.Redis | None = None


def get_redis() -> redis_async.Redis:
    """Lazy singleton."""
    global _client
    if _client is None:
        _client = redis_async.from_url(
            get_settings().redis_url,
            decode_responses=True,
        )
    return _client
