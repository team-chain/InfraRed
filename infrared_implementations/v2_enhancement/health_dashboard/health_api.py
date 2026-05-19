"""
InfraRed v2 — 헬스체크 API
고도화_설계서_v2.0.docx Phase 1-C

HealthDashboard.jsx와 연동되는 FastAPI 엔드포인트.
Heartbeat 30초 구조를 활용해 에이전트/워커 상태 집계.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta

from fastapi import APIRouter, Request

health_router = APIRouter(prefix="/api/v1/health", tags=["health"])


@health_router.get("/agents")
async def get_agents_health(request: Request):
    """에이전트 Heartbeat 기반 상태 목록"""
    db_pool   = request.app.state.db_pool
    tenant_id = request.headers.get("X-Tenant-ID", "global")

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                a.id            AS agent_id,
                a.hostname,
                a.ip_address,
                a.version,
                a.last_heartbeat,
                a.is_active,
                COUNT(s.id) FILTER (
                    WHERE s.created_at > NOW() - INTERVAL '1 day'
                ) AS signals_today
            FROM agents a
            LEFT JOIN signals s ON s.agent_id = a.id
            WHERE a.tenant_id = $1
            GROUP BY a.id
            ORDER BY a.last_heartbeat DESC NULLS LAST
            """,
            tenant_id,
        )
    return [dict(row) for row in rows]


@health_router.get("/workers")
async def get_workers_health(request: Request):
    """워커 프로세스 상태 (Redis에서 heartbeat 조회)"""
    redis     = request.app.state.redis
    tenant_id = request.headers.get("X-Tenant-ID", "global")

    worker_names = ["detection_worker", "incident_worker", "bedrock_worker"]
    workers = []
    for name in worker_names:
        key  = f"worker:heartbeat:{tenant_id}:{name}"
        raw  = await redis.hgetall(key)
        data = {k.decode(): v.decode() for k, v in raw.items()} if raw else {}
        workers.append({
            "name":           name,
            "status":         data.get("status", "unknown"),
            "last_activity":  data.get("last_activity"),
            "processed_count": int(data.get("processed_count", 0)),
            "error_count":     int(data.get("error_count", 0)),
            "lag":             int(data.get("queue_lag", 0)),
        })
    return workers


@health_router.get("/metrics")
async def get_health_metrics(request: Request):
    """오늘 요약 메트릭"""
    db_pool   = request.app.state.db_pool
    tenant_id = request.headers.get("X-Tenant-ID", "global")

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day')
                    AS incidents_today,
                AVG(
                    EXTRACT(EPOCH FROM (first_response_at - created_at)) / 60
                ) FILTER (
                    WHERE first_response_at IS NOT NULL
                    AND created_at > NOW() - INTERVAL '7 days'
                ) AS avg_mttd_minutes
            FROM incidents
            WHERE tenant_id = $1
            """,
            tenant_id,
        )
        llm_row = await conn.fetchrow(
            """
            SELECT COUNT(*) AS llm_calls_today
            FROM llm_results
            WHERE tenant_id=$1 AND created_at > NOW() - INTERVAL '1 day'
            """,
            tenant_id,
        )

    return {
        "incidents_today":   row["incidents_today"]    or 0,
        "avg_mttd_minutes":  round(row["avg_mttd_minutes"] or 0, 1),
        "llm_calls_today":   llm_row["llm_calls_today"] or 0,
    }


# ─────────────────────────────────────────────────────────────
# 워커 Heartbeat 업데이트 유틸 (각 워커에서 호출)
# ─────────────────────────────────────────────────────────────
async def update_worker_heartbeat(
    redis,
    tenant_id:       str,
    worker_name:     str,
    processed_count: int = 0,
    error_count:     int = 0,
    queue_lag:       int = 0,
) -> None:
    key = f"worker:heartbeat:{tenant_id}:{worker_name}"
    await redis.hset(key, mapping={
        "status":          "running",
        "last_activity":   datetime.utcnow().isoformat(),
        "processed_count": processed_count,
        "error_count":     error_count,
        "queue_lag":       queue_lag,
    })
    await redis.expire(key, 120)  # 2분 TTL — 갱신 없으면 unknown 처리
