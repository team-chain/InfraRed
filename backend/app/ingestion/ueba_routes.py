"""
UEBA (User and Entity Behavior Analytics) API 라우터.
v4.0 설계서 §7 참조.

엔드포인트:
  GET  /api/v1/ueba/status              — UEBA 활성화 여부 + 모델 상태
  POST /api/v1/ueba/score               — 단일 사용자 행동 이상도 점수 조회
  POST /api/v1/ueba/training/trigger    — 학습 수동 트리거 (owner 전용)
  POST /api/v1/ueba/collection/trigger  — 일일 수집 수동 트리거 (owner 전용)
  GET  /api/v1/ueba/profiles            — 최근 사용자 프로파일 목록
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.config import get_settings
from app.db.connection import get_session
from app.iam.rbac_v2 import require_any_role, require_role

router = APIRouter(prefix="/api/v1/ueba", tags=["ueba"])
log = logging.getLogger(__name__)

settings = get_settings()


# ─── 요청/응답 모델 ────────────────────────────────────────────────────────────

class ScoreRequest(BaseModel):
    user: str
    date: str | None = None  # YYYY-MM-DD, None 이면 오늘


class ScoreResponse(BaseModel):
    user: str
    date: str
    raw_score: float
    novelty_bonus: float
    is_anomalous: bool
    model_type: str  # isolation_forest | autoencoder | disabled


class TrainingTriggerResponse(BaseModel):
    status: str
    profiles: int | None = None
    isolation_forest: bool | None = None
    autoencoder: bool | None = None
    detail: str | None = None


# ─── GET /api/v1/ueba/status ─────────────────────────────────────────────────

@router.get("/status")
async def ueba_status(
    claims: dict = Depends(require_any_role(*["analyst", "security_manager", "owner", "admin"])),
) -> dict:
    """UEBA 활성화 여부 및 모델 상태 반환."""
    if not settings.ueba_enabled:
        return {"enabled": False, "message": "UEBA가 비활성화되어 있습니다. UEBA_ENABLED=true 설정 필요."}

    tenant_id = claims["tenant_id"]

    # 최근 프로파일 수 조회
    try:
        async with get_session() as session:
            result = await session.execute(text("""
                SELECT
                    COUNT(*) AS total_profiles,
                    MAX(profile_date) AS latest_date,
                    COUNT(DISTINCT user_account) AS unique_users
                FROM daily_user_profiles
                WHERE tenant_id = :tid
                  AND profile_date >= NOW() - INTERVAL '30 days'
            """), {"tid": tenant_id})
            row = result.fetchone()
    except Exception as e:
        log.warning(f"UEBA status DB query failed: {e}")
        row = None

    total = int(row.total_profiles) if row and row.total_profiles else 0
    latest = str(row.latest_date) if row and row.latest_date else None
    users = int(row.unique_users) if row and row.unique_users else 0

    is_silent = total < settings.ueba_silent_days
    return {
        "enabled": True,
        "silent_mode": is_silent,
        "total_profiles_30d": total,
        "unique_users_30d": users,
        "latest_profile_date": latest,
        "silent_days_remaining": max(0, settings.ueba_silent_days - total) if is_silent else 0,
        "model_bucket": settings.ueba_model_bucket,
    }


# ─── POST /api/v1/ueba/score ─────────────────────────────────────────────────

@router.post("/score", response_model=ScoreResponse)
async def score_user(
    body: ScoreRequest,
    claims: dict = Depends(require_any_role(*["analyst", "security_manager", "owner", "admin"])),
) -> ScoreResponse:
    """특정 사용자의 오늘 행동 이상도 점수 반환."""
    if not settings.ueba_enabled:
        raise HTTPException(status_code=503, detail="UEBA가 비활성화 상태입니다.")

    tenant_id = claims["tenant_id"]
    target_date = body.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    from app.workers.ueba.features import extract_daily_profile_from_db
    from app.workers.ueba.worker import score_behavior

    try:
        profile = await extract_daily_profile_from_db(tenant_id, body.user, target_date)
        raw_score, novelty_bonus = score_behavior(tenant_id, profile)
    except Exception as e:
        log.error(f"UEBA scoring error: {e}")
        raise HTTPException(status_code=500, detail=f"UEBA 점수 계산 실패: {e}")

    # Autoencoder 사용 여부 판별
    from app.workers.ueba.autoencoder import AutoencoderModel
    ae = AutoencoderModel(tenant_id)
    ae_loaded = ae._load_from_s3()
    model_type = "autoencoder" if (ae_loaded and ae._trained) else "isolation_forest"

    return ScoreResponse(
        user=body.user,
        date=target_date,
        raw_score=raw_score,
        novelty_bonus=novelty_bonus,
        is_anomalous=novelty_bonus > 0,
        model_type=model_type,
    )


# ─── POST /api/v1/ueba/training/trigger ──────────────────────────────────────

@router.post("/training/trigger", response_model=TrainingTriggerResponse)
async def trigger_training(
    claims: dict = Depends(require_role("owner")),
) -> TrainingTriggerResponse:
    """UEBA 모델 학습을 수동으로 트리거 (owner 전용)."""
    if not settings.ueba_enabled:
        raise HTTPException(status_code=503, detail="UEBA가 비활성화 상태입니다.")

    tenant_id = claims["tenant_id"]

    from app.workers.ueba.worker import run_ueba_training
    result = await run_ueba_training(tenant_id)

    return TrainingTriggerResponse(
        status=result.get("status", "unknown"),
        profiles=result.get("profiles"),
        isolation_forest=result.get("isolation_forest"),
        autoencoder=result.get("autoencoder"),
        detail=result.get("detail"),
    )


# ─── POST /api/v1/ueba/collection/trigger ────────────────────────────────────

@router.post("/collection/trigger")
async def trigger_collection(
    date: str | None = None,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """일일 행동 프로파일 수집을 수동으로 트리거 (owner 전용)."""
    if not settings.ueba_enabled:
        raise HTTPException(status_code=503, detail="UEBA가 비활성화 상태입니다.")

    tenant_id = claims["tenant_id"]

    from app.workers.ueba.worker import run_ueba_daily_collection
    return await run_ueba_daily_collection(tenant_id, date)


# ─── GET /api/v1/ueba/profiles ───────────────────────────────────────────────

@router.get("/profiles")
async def list_profiles(
    limit: int = 50,
    user: str | None = None,
    claims: dict = Depends(require_any_role(*["analyst", "security_manager", "owner", "admin"])),
) -> dict:
    """최근 사용자 행동 프로파일 목록 반환."""
    if not settings.ueba_enabled:
        raise HTTPException(status_code=503, detail="UEBA가 비활성화 상태입니다.")

    tenant_id = claims["tenant_id"]
    conditions = ["tenant_id = :tid"]
    params: dict[str, Any] = {"tid": tenant_id, "limit": min(limit, 200)}

    if user:
        conditions.append("user_account = :user")
        params["user"] = user

    where = " AND ".join(conditions)

    try:
        async with get_session() as session:
            result = await session.execute(text(f"""
                SELECT
                    user_account, profile_date,
                    login_count, failed_login_count,
                    off_hours_login_count, unique_source_ips,
                    new_ip_ratio, sudo_commands, computed_at
                FROM daily_user_profiles
                WHERE {where}
                ORDER BY profile_date DESC, computed_at DESC
                LIMIT :limit
            """), params)
            rows = result.fetchall()
    except Exception as e:
        log.error(f"UEBA profiles query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "count": len(rows),
        "profiles": [
            {
                "user": r.user_account,
                "date": str(r.profile_date),
                "login_count": r.login_count,
                "failed_login_count": r.failed_login_count,
                "off_hours_login_count": r.off_hours_login_count,
                "unique_source_ips": r.unique_source_ips,
                "new_ip_ratio": float(r.new_ip_ratio or 0),
                "sudo_commands": r.sudo_commands,
                "computed_at": r.computed_at.isoformat() if r.computed_at else None,
            }
            for r in rows
        ],
    }
