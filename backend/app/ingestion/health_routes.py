"""Phase 1-C: 헬스체크 대시보드 API (Agent/Worker 상태 시각화).

엔드포인트:
  GET /health/dashboard  - 전체 시스템 상태 (Agent + Worker + Redis)
  GET /health/agents     - Agent별 상태 목록
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.rbac_v2 import require_role
from app.redis_kv.client import get_redis

router = APIRouter(prefix="/health", tags=["health"])

# 설계서 1-C: 임계값 정의
_AGENT_OFFLINE_THRESHOLD_SECONDS = 90
_DETECTION_STREAM_WARN = 100
_LLM_QUEUE_WARN = 10
_LLM_SUCCESS_RATE_WARN = 95.0
_LOCAL_BUFFER_WARN = 1000


@router.get("/dashboard")
async def health_dashboard(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """전체 시스템 헬스체크 대시보드.

    설계서 1-C 표시 항목:
    - Agent Online/Offline (90초 무응답 시 Offline)
    - Detection Stream 지연 (100 이상 시 경고)
    - LLM 큐 깊이 (10 이상 시 경고)
    - LLM 성공률 (95% 미만 시 경고)
    - Discord 전송 실패 (1 이상 시 경고)
    """
    tenant_id = claims["tenant_id"]
    redis = get_redis()
    now = datetime.now(timezone.utc)
    offline_threshold = now - timedelta(seconds=_AGENT_OFFLINE_THRESHOLD_SECONDS)

    # Agent 상태 집계
    async with get_session() as session:
        agent_result = await session.execute(
            text("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE last_heartbeat >= :threshold) as online,
                    COUNT(*) FILTER (WHERE last_heartbeat < :threshold AND last_heartbeat IS NOT NULL) as offline,
                    COUNT(*) FILTER (WHERE last_heartbeat IS NULL) as never_connected
                FROM agents
                WHERE tenant_id = :tenant_id
                  AND (deactivated_at IS NULL OR deactivated_at > NOW())
            """),
            {"tenant_id": tenant_id, "threshold": offline_threshold},
        )
        agent_stats = agent_result.mappings().fetchone()

    # Redis 메트릭
    try:
        detection_stream_len = await redis.xlen("stream:detection") or 0
        llm_queue_len = await redis.llen("queue:llm") or 0
        llm_success_rate_raw = await redis.get(f"metrics:llm_success_rate:{tenant_id}")
        llm_success_rate = float(llm_success_rate_raw) if llm_success_rate_raw else None
        discord_fail_raw = await redis.get(f"metrics:discord_fail:{tenant_id}")
        discord_fail = int(discord_fail_raw) if discord_fail_raw else 0
        redis_ok = True
    except Exception:
        detection_stream_len = 0
        llm_queue_len = 0
        llm_success_rate = None
        discord_fail = 0
        redis_ok = False

    agent_total = int(agent_stats["total"]) if agent_stats else 0
    agent_online = int(agent_stats["online"]) if agent_stats else 0
    agent_offline = int(agent_stats["offline"]) if agent_stats else 0
    agent_never = int(agent_stats["never_connected"]) if agent_stats else 0

    checks = [
        {
            "name": "agent_connectivity",
            "label": "Agent 연결 상태",
            "value": f"{agent_online}/{agent_total}",
            # never_connected 에이전트는 경고에서 제외 (미설치 상태는 정상)
            "status": "warn" if agent_offline > 0 else "ok",
            "detail": f"Offline: {agent_offline}개" + (f", 미연결: {agent_never}개" if agent_never > 0 else ""),
        },
        {
            "name": "detection_stream",
            "label": "Detection Stream 지연",
            "value": detection_stream_len,
            "status": "warn" if detection_stream_len >= _DETECTION_STREAM_WARN else "ok",
            "threshold": _DETECTION_STREAM_WARN,
        },
        {
            "name": "llm_queue",
            "label": "LLM 큐 깊이",
            "value": llm_queue_len,
            "status": "warn" if llm_queue_len >= _LLM_QUEUE_WARN else "ok",
            "threshold": _LLM_QUEUE_WARN,
        },
        {
            "name": "llm_success_rate",
            "label": "LLM 분석 성공률",
            "value": llm_success_rate,
            "status": (
                "warn" if llm_success_rate is not None and llm_success_rate < _LLM_SUCCESS_RATE_WARN
                else "ok" if llm_success_rate is not None
                else "unknown"
            ),
            "threshold": _LLM_SUCCESS_RATE_WARN,
            "unit": "%",
        },
        {
            "name": "discord_fail",
            "label": "Discord 전송 실패",
            "value": discord_fail,
            "status": "warn" if discord_fail >= 1 else "ok",
        },
        {
            "name": "redis",
            "label": "Redis 연결",
            "value": "connected" if redis_ok else "disconnected",
            "status": "ok" if redis_ok else "error",
        },
    ]

    overall = "ok"
    for c in checks:
        if c["status"] == "error":
            overall = "error"
            break
        if c["status"] == "warn":
            overall = "warn"

    return {
        "overall": overall,
        "checked_at": now.isoformat(),
        "checks": checks,
        "agents": {
            "total": agent_total,
            "online": agent_online,
            "offline": agent_offline,
            "never_connected": agent_never,
        },
    }


@router.get("/agents")
async def list_agent_health(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """Agent별 상세 상태 목록.

    설계서 1-C: Agent Online/Offline, 버전, 로컬 버퍼 적재량.
    """
    tenant_id = claims["tenant_id"]
    now = datetime.now(timezone.utc)
    offline_threshold = now - timedelta(seconds=_AGENT_OFFLINE_THRESHOLD_SECONDS)

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT
                    a.agent_id,
                    a.asset_id,
                    a.status,
                    a.last_heartbeat,
                    a.agent_version,
                    a.deactivated_at,
                    ast.hostname,
                    ast.os,
                    CASE
                        WHEN a.deactivated_at IS NOT NULL THEN 'deactivated'
                        WHEN a.last_heartbeat >= :threshold THEN 'online'
                        WHEN a.last_heartbeat IS NULL THEN 'never_connected'
                        ELSE 'offline'
                    END as health_status
                FROM agents a
                LEFT JOIN assets ast ON a.asset_id = ast.asset_id
                WHERE a.tenant_id = :tenant_id
                ORDER BY a.last_heartbeat DESC NULLS LAST
            """),
            {"tenant_id": tenant_id, "threshold": offline_threshold},
        )
        rows = result.mappings().fetchall()

        # 최신 버전 조회
        latest_ver_result = await session.execute(
            text("""
                SELECT version, COUNT(*) as agent_count
                FROM agent_versions
                WHERE tenant_id = :tenant_id
                  AND reported_at > NOW() - INTERVAL '7 days'
                GROUP BY version
                ORDER BY MAX(reported_at) DESC
                LIMIT 1
            """),
            {"tenant_id": tenant_id},
        )
        latest_version_row = latest_ver_result.fetchone()
        latest_version = latest_version_row[0] if latest_version_row else None

    agents = []
    for r in rows:
        last_hb = r["last_heartbeat"]
        seconds_ago = None
        if last_hb:
            if last_hb.tzinfo is None:
                last_hb = last_hb.replace(tzinfo=timezone.utc)
            seconds_ago = int((now - last_hb).total_seconds())

        agents.append({
            "agent_id": r["agent_id"],
            "asset_id": r["asset_id"],
            "hostname": r["hostname"],
            "os": r["os"],
            "health_status": r["health_status"],
            "agent_version": r["agent_version"],
            "version_outdated": (
                r["agent_version"] != latest_version
                if latest_version and r["agent_version"]
                else None
            ),
            "last_heartbeat": last_hb.isoformat() if last_hb else None,
            "seconds_since_heartbeat": seconds_ago,
            "deactivated_at": r["deactivated_at"].isoformat() if r["deactivated_at"] else None,
        })

    return {
        "items": agents,
        "latest_known_version": latest_version,
        "offline_threshold_seconds": _AGENT_OFFLINE_THRESHOLD_SECONDS,
    }
