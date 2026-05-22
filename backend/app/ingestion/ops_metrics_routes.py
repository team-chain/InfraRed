"""Owner-only operations metrics dashboard.

`GET /admin/ops-metrics` aggregates DB · Redis · agent stats into a single
payload for the internal Operations tab. All data is scoped to the caller's
tenant (no cross-tenant leakage).

Response shape:
    {
      "tenant_id": "...",
      "generated_at": "2026-05-22T...",
      "events": {
        "last_24h": 12345,
        "last_7d": 78900
      },
      "incidents": {
        "open": 3,
        "last_24h": {"critical": 1, "high": 2, "medium": 5, "low": 7},
        "last_7d_total": 41
      },
      "agents": {
        "total": 8,
        "online": 7,
        "offline": 1,
        "never_connected": 0
      },
      "redis": {
        "memory_used_mb": 12.4,
        "memory_peak_mb": 18.1,
        "connected_clients": 12,
        "ok": true
      },
      "notifications": {
        "discord_sent_24h": 24,
        "discord_failed_24h": 0,
        "slack_sent_24h": 0,
        "email_sent_24h": 2
      }
    }
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.common.logging import get_logger
from app.db.connection import get_session
from app.iam.rbac_v2 import require_role
from app.redis_kv.client import get_redis

router = APIRouter(prefix="/admin", tags=["admin-ops"])
log = get_logger(__name__)

_AGENT_OFFLINE_THRESHOLD_SECONDS = 90


async def _redis_stats() -> dict:
    """Redis INFO 파싱 — memory + clients."""
    try:
        redis = get_redis()
        info = await redis.info(section="memory")
        clients_info = await redis.info(section="clients")
        used = info.get("used_memory", 0)
        peak = info.get("used_memory_peak", 0)
        return {
            "memory_used_mb": round(int(used) / (1024 * 1024), 2),
            "memory_peak_mb": round(int(peak) / (1024 * 1024), 2),
            "connected_clients": int(clients_info.get("connected_clients", 0)),
            "ok": True,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("ops_metrics_redis_failed", error=str(exc))
        return {
            "memory_used_mb": None,
            "memory_peak_mb": None,
            "connected_clients": None,
            "ok": False,
        }


async def _notification_counts(tenant_id: str) -> dict:
    """Redis counter keys로 알림 발송/실패 수 집계 (단순 24h 카운터)."""
    try:
        redis = get_redis()
        keys = {
            "discord_sent_24h": f"metrics:notif:discord:sent:24h:{tenant_id}",
            "discord_failed_24h": f"metrics:notif:discord:failed:24h:{tenant_id}",
            "slack_sent_24h": f"metrics:notif:slack:sent:24h:{tenant_id}",
            "slack_failed_24h": f"metrics:notif:slack:failed:24h:{tenant_id}",
            "email_sent_24h": f"metrics:notif:email:sent:24h:{tenant_id}",
            "email_failed_24h": f"metrics:notif:email:failed:24h:{tenant_id}",
        }
        out = {}
        for label, key in keys.items():
            v = await redis.get(key)
            out[label] = int(v) if v else 0
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("ops_metrics_notif_failed", error=str(exc))
        return {
            "discord_sent_24h": 0,
            "discord_failed_24h": 0,
            "slack_sent_24h": 0,
            "slack_failed_24h": 0,
            "email_sent_24h": 0,
            "email_failed_24h": 0,
        }


@router.get("/ops-metrics")
async def ops_metrics(
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """운영 메트릭 — owner 전용.

    모든 카운트는 호출자의 tenant_id로 스코프됨.
    """
    tenant_id = claims["tenant_id"]
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)
    agent_offline_threshold = now - timedelta(seconds=_AGENT_OFFLINE_THRESHOLD_SECONDS)

    async with get_session() as session:
        # 이벤트 카운트 (24h / 7d)
        ev_result = await session.execute(
            text("""
                SELECT
                    COUNT(*) FILTER (WHERE ingested_at >= :cutoff_24h) AS last_24h,
                    COUNT(*) FILTER (WHERE ingested_at >= :cutoff_7d)  AS last_7d
                FROM events
                WHERE tenant_id = :tenant_id
                  AND ingested_at >= :cutoff_7d
            """),
            {"tenant_id": tenant_id, "cutoff_24h": cutoff_24h, "cutoff_7d": cutoff_7d},
        )
        ev_row = ev_result.mappings().fetchone()

        # 인시던트 (열린 것 + 24h severity 분포 + 7d 총합)
        inc_open = await session.execute(
            text("""
                SELECT COUNT(*) AS open_count
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND status IN ('OPEN', 'IN_PROGRESS')
            """),
            {"tenant_id": tenant_id},
        )
        open_count = int(inc_open.scalar() or 0)

        inc_24h = await session.execute(
            text("""
                SELECT severity, COUNT(*) AS cnt
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND created_at >= :cutoff_24h
                GROUP BY severity
            """),
            {"tenant_id": tenant_id, "cutoff_24h": cutoff_24h},
        )
        sev_24h: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in inc_24h.mappings():
            sev = (row["severity"] or "").lower()
            if sev in sev_24h:
                sev_24h[sev] = int(row["cnt"])

        inc_7d = await session.execute(
            text("""
                SELECT COUNT(*) AS total
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND created_at >= :cutoff_7d
            """),
            {"tenant_id": tenant_id, "cutoff_7d": cutoff_7d},
        )
        total_7d = int(inc_7d.scalar() or 0)

        # 에이전트 — health_routes와 동일 임계값
        agent_result = await session.execute(
            text("""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE last_heartbeat >= :threshold) AS online,
                    COUNT(*) FILTER (WHERE last_heartbeat <  :threshold AND last_heartbeat IS NOT NULL) AS offline,
                    COUNT(*) FILTER (WHERE last_heartbeat IS NULL) AS never_connected
                FROM agents
                WHERE tenant_id = :tenant_id
                  AND (deactivated_at IS NULL OR deactivated_at > NOW())
            """),
            {"tenant_id": tenant_id, "threshold": agent_offline_threshold},
        )
        agent_row = agent_result.mappings().fetchone()

    redis_stats = await _redis_stats()
    notif_stats = await _notification_counts(tenant_id)

    return {
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "events": {
            "last_24h": int(ev_row["last_24h"] or 0) if ev_row else 0,
            "last_7d": int(ev_row["last_7d"] or 0) if ev_row else 0,
        },
        "incidents": {
            "open": open_count,
            "last_24h": sev_24h,
            "last_7d_total": total_7d,
        },
        "agents": {
            "total": int(agent_row["total"] or 0) if agent_row else 0,
            "online": int(agent_row["online"] or 0) if agent_row else 0,
            "offline": int(agent_row["offline"] or 0) if agent_row else 0,
            "never_connected": int(agent_row["never_connected"] or 0) if agent_row else 0,
        },
        "redis": redis_stats,
        "notifications": notif_stats,
    }
