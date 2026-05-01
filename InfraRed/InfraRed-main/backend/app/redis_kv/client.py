"""Redis client helpers."""
from __future__ import annotations

from functools import lru_cache

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.config import get_settings


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    return Redis.from_url(get_settings().redis_url, decode_responses=True)


async def ensure_group(redis: Redis, stream: str, group: str) -> None:
    try:
        await redis.xgroup_create(stream, group, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
