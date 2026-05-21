"""
UEBA Worker: 사용자 행동 프로파일 수집 + 이상탐지 실행.
EventBridge Lambda 또는 주기적 백그라운드 태스크로 실행.
v4.0 설계서 §7 참조.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.workers.ueba.autoencoder import AutoencoderModel
from app.workers.ueba.features import (
    UserBehaviorFeatures,
    aggregate_daily_profiles,
    extract_daily_profile_from_db,
    save_daily_profile,
)
from app.workers.ueba.model import UEBAModel, get_ueba_model

logger = logging.getLogger(__name__)


async def extract_daily_profile(tenant_id: str, user: str, target_date: str) -> UserBehaviorFeatures:
    """DB에서 해당 날짜의 사용자 행동 데이터 추출."""
    return await extract_daily_profile_from_db(tenant_id, user, target_date)


async def run_ueba_daily_collection(tenant_id: str, target_date: str | None = None) -> dict:
    """
    일일 사용자 행동 프로파일 수집 및 저장.
    매일 새벽 2시 Lambda EventBridge로 실행.
    """
    settings = get_settings()
    if not settings.ueba_enabled:
        return {"status": "disabled"}

    if target_date is None:
        target_date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")

    try:
        profiles = await aggregate_daily_profiles(tenant_id, target_date)
        saved_count = 0
        for profile in profiles:
            try:
                await save_daily_profile(profile)
                saved_count += 1
            except Exception as e:
                logger.warning("Profile save failed for %s: %s", profile.user, e)

        logger.info("UEBA daily collection: tenant=%s, date=%s, saved=%d", tenant_id, target_date, saved_count)
        return {"status": "ok", "date": target_date, "users_profiled": saved_count}
    except Exception as e:
        logger.error("UEBA daily collection failed: %s", e)
        return {"status": "error", "detail": str(e)}


async def run_ueba_training(tenant_id: str) -> dict:
    """
    주 1회 모델 재학습.
    최근 30일 프로파일로 Isolation Forest + Autoencoder 학습.
    """
    settings = get_settings()
    if not settings.ueba_enabled:
        return {"status": "disabled"}

    from sqlalchemy import text

    from app.db.connection import get_session

    try:
        async with get_session() as session:
            result = await session.execute(text("""
                SELECT
                    user_account, profile_date,
                    login_hour_mean, login_hour_std, login_count,
                    off_hours_login_count, unique_source_ips, unique_countries,
                    new_ip_ratio, failed_login_count, success_after_failure,
                    commands_executed, sudo_commands, files_accessed,
                    session_duration_mean, concurrent_sessions
                FROM daily_user_profiles
                WHERE tenant_id = :tenant_id
                  AND profile_date >= NOW() - INTERVAL '30 days'
                ORDER BY profile_date DESC
            """), {"tenant_id": tenant_id})
            rows = result.fetchall()
    except Exception as e:
        logger.error("UEBA training DB query failed: %s", e)
        return {"status": "error", "detail": str(e)}

    profiles = [
        UserBehaviorFeatures(
            tenant_id=tenant_id,
            user=r.user_account,
            date=str(r.profile_date),
            login_hour_mean=float(r.login_hour_mean or 0),
            login_hour_std=float(r.login_hour_std or 0),
            login_count=int(r.login_count or 0),
            off_hours_login_count=int(r.off_hours_login_count or 0),
            unique_source_ips=int(r.unique_source_ips or 0),
            unique_countries=int(r.unique_countries or 0),
            new_ip_ratio=float(r.new_ip_ratio or 0),
            failed_login_count=int(r.failed_login_count or 0),
            success_after_failure=int(r.success_after_failure or 0),
            commands_executed=int(r.commands_executed or 0),
            sudo_commands=int(r.sudo_commands or 0),
            files_accessed=int(r.files_accessed or 0),
            session_duration_mean=float(r.session_duration_mean or 0),
            concurrent_sessions=int(r.concurrent_sessions or 0),
        )
        for r in rows
    ]

    if len(profiles) < settings.ueba_silent_days:
        return {
            "status": "silent_mode",
            "profiles": len(profiles),
            "required": settings.ueba_silent_days,
        }

    iso_model = get_ueba_model(tenant_id)
    iso_trained = iso_model.train(profiles)

    ae_trained = False
    if len(profiles) >= AutoencoderModel.MIN_TRAINING_DAYS:
        ae_model = AutoencoderModel(tenant_id)
        ae_trained = ae_model.train(profiles)

    logger.info("UEBA training: tenant=%s, profiles=%d, iso=%s, ae=%s",
                tenant_id, len(profiles), iso_trained, ae_trained)
    return {
        "status": "trained",
        "profiles": len(profiles),
        "isolation_forest": iso_trained,
        "autoencoder": ae_trained,
    }


def score_behavior(tenant_id: str, profile: UserBehaviorFeatures) -> tuple[float, float]:
    """
    사용자 행동 이상도 평가.
    30일+ 데이터면 Autoencoder, 그 미만이면 Isolation Forest.
    Returns: (raw_score, novelty_bonus)
    """
    settings = get_settings()
    if not settings.ueba_enabled:
        return 0.0, 0.0

    ae_model = AutoencoderModel(tenant_id)
    loaded = ae_model._load_from_s3()
    if loaded and ae_model._trained:
        bonus = ae_model.to_novelty_bonus(profile)
        score = ae_model.score(profile)
        return score, bonus

    iso_model = get_ueba_model(tenant_id)
    score = iso_model.score(profile)
    bonus = UEBAModel.to_novelty_bonus(score)
    return score, bonus


def lambda_handler(event: dict, context) -> dict:
    """Lambda 진입점 (EventBridge 주 1회 학습)."""
    tenant_ids = event.get("tenant_ids", [])
    results = []
    for tid in tenant_ids:
        result = asyncio.run(run_ueba_training(tid))
        results.append({"tenant_id": tid, **result})
    return {"results": results}


def lambda_handler_collection(event: dict, context) -> dict:
    """Lambda 진입점 (EventBridge 매일 데이터 수집)."""
    tenant_id = event.get("tenant_id", "")
    target_date = event.get("date")
    if not tenant_id:
        return {"status": "error", "detail": "tenant_id required"}
    return asyncio.run(run_ueba_daily_collection(tenant_id, target_date))
