"""Demo Data Cleanup CronJob (설계서 17.3).

실행 주기: 매일 UTC 자정 (APScheduler 또는 asyncio.sleep 루프)

삭제 순서 (설계서 17.3 Cleanup 순서):
  1. PostgreSQL demo_signals 삭제 (개인정보 우선 삭제)
  2. Redis demo TTL 키 삭제 시도
  3. Redis 삭제 실패 시 TTL 24시간 자동 만료로 fallback

모든 삭제 작업은 idempotent하게 설계.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import text

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.connection import get_session
from app.redis_kv.client import get_redis


configure_logging()
log = get_logger(__name__)


async def cleanup_expired_demo_signals() -> dict:
    """만료된 demo_signals 삭제 (expires_at < NOW()).

    Returns:
        {"deleted_db": int, "redis_keys_deleted": int, "redis_fallback": int}
    """
    deleted_db = 0
    redis_keys_deleted = 0
    redis_fallback = 0

    # ── Step 1: PostgreSQL demo_signals 삭제 ─────────────────────────────────
    try:
        async with get_session() as session:
            result = await session.execute(
                text("""
                    DELETE FROM demo_signals
                    WHERE expires_at < NOW()
                    RETURNING demo_signal_id, source_ip_hash
                """)
            )
            rows = result.fetchall()
            deleted_db = len(rows)
            await session.commit()
            log.info("demo_cleanup_db_done", deleted_count=deleted_db)
    except Exception as exc:
        log.exception("demo_cleanup_db_failed", error=str(exc))

    # ── Step 2: Redis honeypot:visit TTL 키 삭제 ─────────────────────────────
    # TTL 키는 24h로 자동 만료되므로 별도 삭제 불필요한 경우가 대부분
    # 명시적 삭제는 tenant 데이터 일괄 삭제 시 사용
    redis = get_redis()
    settings = get_settings()
    try:
        pattern = f"tenant:{settings.tenant_id}:honeypot:visit:*"
        cursor = b"0"
        while True:
            cursor, keys = await redis.scan(cursor, match=pattern, count=100)
            for key in keys:
                ttl = await redis.ttl(key)
                if ttl <= 0:  # 이미 만료됐거나 TTL 없음
                    await redis.delete(key)
                    redis_keys_deleted += 1
            if cursor == b"0":
                break
        log.info("demo_cleanup_redis_done", deleted_count=redis_keys_deleted)
    except Exception as exc:
        redis_fallback += 1
        log.warning("demo_cleanup_redis_failed", error=str(exc), note="TTL 24h 자동 만료로 fallback")

    return {
        "deleted_db": deleted_db,
        "redis_keys_deleted": redis_keys_deleted,
        "redis_fallback": redis_fallback,
        "run_at": datetime.now(timezone.utc).isoformat(),
    }


async def purge_demo_tenant(tenant_id: str) -> dict:
    """발표 종료 후 demo tenant 데이터 수동 일괄 삭제 (설계서 17.3).

    모든 demo_signals + Redis honeypot 키 전체 삭제.
    """
    deleted_db = 0
    redis_keys_deleted = 0

    async with get_session() as session:
        result = await session.execute(
            text("DELETE FROM demo_signals WHERE tenant_id = :tid RETURNING demo_signal_id"),
            {"tid": tenant_id},
        )
        deleted_db = len(result.fetchall())
        await session.commit()

    redis = get_redis()
    try:
        pattern = f"tenant:{tenant_id}:honeypot:visit:*"
        cursor = b"0"
        while True:
            cursor, keys = await redis.scan(cursor, match=pattern, count=100)
            if keys:
                await redis.delete(*keys)
                redis_keys_deleted += len(keys)
            if cursor == b"0":
                break
    except Exception as exc:
        log.warning("purge_demo_redis_failed", tenant_id=tenant_id, error=str(exc))

    log.info("demo_tenant_purged", tenant_id=tenant_id, deleted_db=deleted_db)
    return {"tenant_id": tenant_id, "deleted_db": deleted_db, "redis_keys_deleted": redis_keys_deleted}


def _seconds_until_next_utc_midnight() -> float:
    """다음 UTC 자정까지 남은 초 계산."""
    now = datetime.now(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    from datetime import timedelta
    next_midnight = midnight + timedelta(days=1)
    return (next_midnight - now).total_seconds()


async def main() -> None:
    """매일 UTC 자정에 cleanup 실행하는 루프."""
    log.info("demo_cleanup_worker_started")
    while True:
        wait_sec = _seconds_until_next_utc_midnight()
        log.info("demo_cleanup_next_run_in", seconds=int(wait_sec))
        await asyncio.sleep(wait_sec)

        result = await cleanup_expired_demo_signals()
        log.info("demo_cleanup_completed", **result)

        # 다음 실행까지 최소 60초 대기 (자정 직후 중복 실행 방지)
        await asyncio.sleep(60)


if __name__ == "__main__":
    asyncio.run(main())
