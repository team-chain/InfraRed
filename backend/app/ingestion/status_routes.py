"""Public status page endpoint (no auth required).

`GET /status/public` returns the health of core components so an external
status page (e.g. status.infrared.kr) or any monitoring tool can poll without
credentials. Returns enough info for green/yellow/red rendering but never
leaks per-tenant data.

Response shape:
    {
      "overall": "operational" | "degraded" | "down",
      "checked_at": "2026-05-22T08:00:00Z",
      "components": [
        {
          "id": "api",
          "name": "API",
          "description": "...",
          "status": "operational" | "degraded" | "down",
          "latency_ms": 5,
          "message": null  // optional human-readable note
        },
        ...
      ]
    }
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from app.common.logging import get_logger
from app.db.connection import get_session
from app.redis_kv.client import get_redis

router = APIRouter(prefix="/status", tags=["status"])
log = get_logger(__name__)

# 임계값
_DB_DEGRADED_MS = 500
_REDIS_DEGRADED_MS = 200


async def _check_db() -> dict:
    """PostgreSQL — SELECT 1 latency 측정."""
    start = time.perf_counter()
    try:
        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        latency_ms = int((time.perf_counter() - start) * 1000)
        status = "operational" if latency_ms < _DB_DEGRADED_MS else "degraded"
        return {
            "id": "database",
            "name": "Database",
            "description": "PostgreSQL — 이벤트·인시던트 저장소",
            "status": status,
            "latency_ms": latency_ms,
            "message": f"응답 시간 {latency_ms}ms가 임계값(500ms)을 초과했습니다."
            if status == "degraded"
            else None,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("status_check_db_failed", error=str(exc))
        return {
            "id": "database",
            "name": "Database",
            "description": "PostgreSQL — 이벤트·인시던트 저장소",
            "status": "down",
            "latency_ms": None,
            "message": "데이터베이스 연결 실패",
        }


async def _check_redis() -> dict:
    """Redis — PING latency 측정."""
    start = time.perf_counter()
    try:
        redis = get_redis()
        pong = await redis.ping()
        latency_ms = int((time.perf_counter() - start) * 1000)
        if not pong:
            return {
                "id": "cache",
                "name": "Cache",
                "description": "Redis — 스트림·세션·rate limit",
                "status": "down",
                "latency_ms": None,
                "message": "Redis PING 응답 실패",
            }
        status = "operational" if latency_ms < _REDIS_DEGRADED_MS else "degraded"
        return {
            "id": "cache",
            "name": "Cache",
            "description": "Redis — 스트림·세션·rate limit",
            "status": status,
            "latency_ms": latency_ms,
            "message": None,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("status_check_redis_failed", error=str(exc))
        return {
            "id": "cache",
            "name": "Cache",
            "description": "Redis — 스트림·세션·rate limit",
            "status": "down",
            "latency_ms": None,
            "message": "Redis 연결 실패",
        }


async def _check_detection_workers() -> dict:
    """Detection worker — Redis stream lag로 추정.

    detection-workers 그룹의 pending message 수가 과도하면 degraded.
    """
    try:
        redis = get_redis()
        # 모든 테넌트 stream의 lag 합산 — 정확하진 않지만 충분
        total_pending = 0
        async for key in redis.scan_iter(match="tenant:*:stream:events:raw", count=100):
            try:
                info = await redis.xinfo_groups(key)
                for group in info:
                    if group.get("name") == b"detection-workers" or group.get("name") == "detection-workers":
                        total_pending += int(group.get(b"pending", group.get("pending", 0)) or 0)
            except Exception:
                continue
        if total_pending > 1000:
            return {
                "id": "detection",
                "name": "Detection Engine",
                "description": "실시간 침해 탐지 워커",
                "status": "degraded",
                "latency_ms": None,
                "message": f"처리 대기 중인 이벤트 {total_pending}개 — 처리 지연 가능성",
            }
        return {
            "id": "detection",
            "name": "Detection Engine",
            "description": "실시간 침해 탐지 워커",
            "status": "operational",
            "latency_ms": None,
            "message": None,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("status_check_detection_failed", error=str(exc))
        # 워커 상태 확인 실패는 down으로 단정하지 않음 (Redis가 down이면 위 cache에서 잡힘)
        return {
            "id": "detection",
            "name": "Detection Engine",
            "description": "실시간 침해 탐지 워커",
            "status": "operational",
            "latency_ms": None,
            "message": None,
        }


@router.get("/public")
async def public_status() -> dict:
    """공개 상태 페이지용 헬스체크 (인증 불필요).

    외부 status 페이지, 모니터링 도구가 30초 간격으로 폴링.
    개별 테넌트 정보는 절대 포함하지 않음.
    """
    # API 자기 자신은 응답 시점에 0ms로 처리 (요청이 처리되고 있으면 API는 살아 있음)
    api_component = {
        "id": "api",
        "name": "API",
        "description": "Backend API · ingestion endpoint",
        "status": "operational",
        "latency_ms": 0,
        "message": None,
    }

    # 나머지 컴포넌트는 병렬 체크
    db, cache, detection = await asyncio.gather(
        _check_db(),
        _check_redis(),
        _check_detection_workers(),
    )

    components = [api_component, db, cache, detection]

    # 전체 상태 = 가장 나쁜 컴포넌트 상태
    if any(c["status"] == "down" for c in components):
        overall = "down"
    elif any(c["status"] == "degraded" for c in components):
        overall = "degraded"
    else:
        overall = "operational"

    return {
        "overall": overall,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "components": components,
    }
