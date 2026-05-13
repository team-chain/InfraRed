"""Phase 1-B: 알림 그룹핑 (Alert Fatigue 방지).

설계서 1-B:
- Redis: 실시간 5분 윈도우 그룹핑
- PostgreSQL: 운영 이력 보관 (alert_groups)
- 그룹핑 기준: source_ip + asset_id + 300초 윈도우
- Discord/Slack 알림은 그룹 단위 1건만 발송
- 추가 탐지 시 "N개 추가 탐지" 업데이트 메시지
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

from app.common.logging import get_logger
from app.db.connection import get_session
from app.redis_kv.client import get_redis

log = get_logger(__name__)

_GROUP_WINDOW_SECONDS = 300  # 5분
_REDIS_KEY_TTL = _GROUP_WINDOW_SECONDS * 2


def _group_key(tenant_id: str, source_ip: Optional[str], asset_id: Optional[str]) -> str:
    """Redis 그룹핑 키 생성."""
    ip_part = source_ip or "noip"
    asset_part = asset_id or "noasset"
    return f"alert_group:{tenant_id}:{ip_part}:{asset_part}"


async def get_or_create_group(
    tenant_id: str,
    source_ip: Optional[str],
    asset_id: Optional[str],
    rule_id: str,
    severity: str,
) -> dict:
    """시그널에 대한 알림 그룹을 찾거나 생성.

    Returns:
        dict: {
            group_id: str,
            is_new: bool,       # True=새 그룹(알림 발송 필요), False=기존(업데이트만)
            signal_count: int,
        }
    """
    redis = get_redis()
    redis_key = _group_key(tenant_id, source_ip, asset_id)
    now = datetime.now(timezone.utc)

    # Redis에서 현재 윈도우 내 그룹 확인
    existing_raw = await redis.get(redis_key)

    if existing_raw:
        # 기존 그룹 업데이트
        group_data = json.loads(existing_raw)
        group_id = group_data["group_id"]
        signal_count = group_data.get("signal_count", 1) + 1

        # rule_ids 업데이트
        rule_ids = list(set(group_data.get("rule_ids", []) + [rule_id]))

        # severity 최고값 유지
        severity_rank = {"info": 0, "medium": 1, "high": 2, "critical": 3}
        current_sev = group_data.get("severity", "info")
        if severity_rank.get(severity, 0) > severity_rank.get(current_sev, 0):
            current_sev = severity

        group_data.update({
            "signal_count": signal_count,
            "rule_ids": rule_ids,
            "severity": current_sev,
            "last_seen_at": now.isoformat(),
        })

        # Redis 갱신 (TTL 연장)
        await redis.set(redis_key, json.dumps(group_data), ex=_REDIS_KEY_TTL)

        # PostgreSQL 업데이트
        try:
            async with get_session() as session:
                await session.execute(
                    text("""
                        UPDATE alert_groups
                        SET signal_count = :count,
                            last_seen_at = :last_seen,
                            rule_ids = :rule_ids,
                            severity = :severity
                        WHERE id = :group_id
                    """),
                    {
                        "count": signal_count,
                        "last_seen": now,
                        "rule_ids": rule_ids,
                        "severity": current_sev,
                        "group_id": group_id,
                    },
                )
                await session.commit()
        except Exception as exc:
            log.warning("alert_group_db_update_failed", group_id=group_id, error=str(exc))

        return {"group_id": group_id, "is_new": False, "signal_count": signal_count}

    else:
        # 새 그룹 생성
        try:
            async with get_session() as session:
                result = await session.execute(
                    text("""
                        INSERT INTO alert_groups
                            (tenant_id, source_ip, asset_id, rule_ids, severity, first_seen_at, last_seen_at)
                        VALUES
                            (:tenant_id, CAST(:source_ip AS INET), :asset_id, :rule_ids, :severity, :now, :now)
                        RETURNING id::text
                    """),
                    {
                        "tenant_id": tenant_id,
                        "source_ip": source_ip,
                        "asset_id": asset_id,
                        "rule_ids": [rule_id],
                        "severity": severity,
                        "now": now,
                    },
                )
                group_id = result.scalar()
                await session.commit()
        except Exception as exc:
            log.error("alert_group_db_create_failed", error=str(exc))
            group_id = f"tmp-{tenant_id}-{int(now.timestamp())}"

        group_data = {
            "group_id": group_id,
            "tenant_id": tenant_id,
            "source_ip": source_ip,
            "asset_id": asset_id,
            "rule_ids": [rule_id],
            "severity": severity,
            "signal_count": 1,
            "first_seen_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
        }
        await redis.set(redis_key, json.dumps(group_data), ex=_REDIS_KEY_TTL)

        return {"group_id": group_id, "is_new": True, "signal_count": 1}


async def mark_group_notified(group_id: str) -> None:
    """그룹 알림 발송 완료 표시."""
    try:
        async with get_session() as session:
            await session.execute(
                text("""
                    UPDATE alert_groups
                    SET notified_at = NOW()
                    WHERE id = :group_id
                """),
                {"group_id": group_id},
            )
            await session.commit()
    except Exception as exc:
        log.warning("mark_group_notified_failed", group_id=group_id, error=str(exc))


async def list_alert_groups(tenant_id: str, limit: int = 50) -> list[dict]:
    """현재 활성 알림 그룹 목록."""
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT id::text, source_ip::text, asset_id, rule_ids,
                       severity, signal_count, status,
                       first_seen_at, last_seen_at, notified_at
                FROM alert_groups
                WHERE tenant_id = :tenant_id
                  AND status = 'open'
                  AND last_seen_at > NOW() - INTERVAL '24 hours'
                ORDER BY last_seen_at DESC
                LIMIT :limit
            """),
            {"tenant_id": tenant_id, "limit": limit},
        )
        rows = result.mappings().fetchall()

    return [
        {
            "id": r["id"],
            "source_ip": r["source_ip"],
            "asset_id": r["asset_id"],
            "rule_ids": r["rule_ids"] or [],
            "severity": r["severity"],
            "signal_count": r["signal_count"],
            "status": r["status"],
            "first_seen_at": r["first_seen_at"].isoformat() if r["first_seen_at"] else None,
            "last_seen_at": r["last_seen_at"].isoformat() if r["last_seen_at"] else None,
            "notified_at": r["notified_at"].isoformat() if r["notified_at"] else None,
        }
        for r in rows
    ]
