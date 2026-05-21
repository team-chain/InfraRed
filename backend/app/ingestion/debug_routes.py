"""Debug / 개발 전용 API (설계서 v3 §11.1).

엔드포인트:
  POST /api/v1/debug/replay-events  — 이벤트 재생 (개발/스테이징 전용)
  GET  /api/v1/debug/signals        — 최근 시그널 목록 (탐지 디버깅)

⚠️  보안: 운영(prod) 환경에서 이 엔드포인트는 403을 반환한다.
    env=dev 또는 env=staging일 때만 동작하며,
    role=owner 권한이 필요하다.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.config import get_settings
from app.db.connection import get_session, SessionLocal
from app.iam.rbac_v2 import require_role
from app.redis_kv import streams
from app.redis_kv.client import get_redis

router = APIRouter(prefix="/api/v1/debug", tags=["debug"])
log = logging.getLogger(__name__)

settings = get_settings()


async def _get_db():
    """FastAPI Depends용 세션 dependency."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def _require_non_prod() -> None:
    """운영 환경에서 디버그 API 접근 차단."""
    if settings.env == "prod":
        raise HTTPException(
            status_code=403,
            detail="디버그 API는 운영(prod) 환경에서 사용할 수 없습니다.",
        )


# ─── Request / Response 모델 ─────────────────────────────────────────────────

class ReplayEventItem(BaseModel):
    """단일 이벤트 재생 항목."""
    event_type: str
    source_ip: str | None = None
    user: str | None = None
    asset_id: str
    timestamp: str | None = None  # ISO 8601; None이면 현재 시각 사용
    data: dict[str, Any] = {}


class ReplayEventsRequest(BaseModel):
    """이벤트 재생 요청."""
    events: list[ReplayEventItem]
    dry_run: bool = False  # True이면 Redis에 실제로 적재하지 않음


class ReplayEventsResponse(BaseModel):
    replayed: int
    dry_run: bool
    event_ids: list[str]


# ─── POST /api/v1/debug/replay-events ───────────────────────────────────────

@router.post("/replay-events", response_model=ReplayEventsResponse)
async def replay_events(
    payload: ReplayEventsRequest,
    claims: dict = Depends(require_role("owner")),
    redis=Depends(get_redis),
) -> ReplayEventsResponse:
    """BAS 시나리오 이벤트를 Redis 스트림에 재생 (탐지 파이프라인 E2E 검증).

    실제 탐지 파이프라인을 통해 이벤트를 처리하므로
    Detection Worker → Incident Worker → Policy Engine 전체가 동작합니다.

    사용 예:
      POST /api/v1/debug/replay-events
      {
        "events": [
          {
            "event_type": "ssh_login_failed",
            "source_ip": "45.33.100.1",
            "user": "root",
            "asset_id": "asset-prod-web-01",
            "data": {"attempt": 1}
          }
        ],
        "dry_run": false
      }
    """
    _require_non_prod()

    tenant_id = claims.get("tenant_id", "debug-tenant")
    event_ids: list[str] = []

    for item in payload.events:
        ts = item.timestamp or datetime.now(timezone.utc).isoformat()
        event_id = f"dbg-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        event_ids.append(event_id)

        envelope = {
            "event_id":   event_id,
            "tenant_id":  tenant_id,
            "asset_id":   item.asset_id,
            "event_type": item.event_type,
            "timestamp":  ts,
            "source_ip":  item.source_ip or "",
            "user":       item.user or "",
            **item.data,
        }

        log.info(
            "debug_replay: event_type=%s asset=%s dry_run=%s",
            item.event_type, item.asset_id, payload.dry_run,
        )

        if not payload.dry_run:
            await redis.xadd(
                streams.events_raw(tenant_id),
                {"payload": json.dumps(envelope)},
                maxlen=10_000,
                approximate=True,
            )

    return ReplayEventsResponse(
        replayed=len(payload.events),
        dry_run=payload.dry_run,
        event_ids=event_ids,
    )


# ─── GET /api/v1/debug/signals ───────────────────────────────────────────────

@router.get("/signals")
async def get_recent_signals(
    limit: int = 50,
    rule_id: str | None = None,
    asset_id: str | None = None,
    claims: dict = Depends(require_role("analyst")),
    session=Depends(_get_db),
) -> dict:
    """최근 시그널 목록 조회 (Threat Hunting 디버깅용).

    탐지된 Signal을 조회하여 탐지 파이프라인 동작을 확인한다.
    rule_id, asset_id로 필터링 가능.
    """
    _require_non_prod()

    tenant_id = claims.get("tenant_id")
    conditions = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": min(limit, 200)}

    if rule_id:
        conditions.append("rule_id = :rule_id")
        params["rule_id"] = rule_id
    if asset_id:
        conditions.append("asset_id = :asset_id")
        params["asset_id"] = asset_id

    where = " AND ".join(conditions)
    rows = await session.execute(
        text(f"""
            SELECT
                id, rule_id, severity, source_ip, asset_id,
                created_at, cti_result, novelty_score,
                raw_event
            FROM signals
            WHERE {where}
            ORDER BY created_at DESC
            LIMIT :limit
        """),
        params,
    )
    signals = [dict(r._mapping) for r in rows]

    return {
        "count": len(signals),
        "signals": [
            {
                **s,
                "created_at": s["created_at"].isoformat() if s.get("created_at") else None,
                "cti_result": s.get("cti_result"),
            }
            for s in signals
        ],
    }
