"""
UEBA 피처 추출 - 사용자 행동 프로파일링.
v4.0 설계서 §7 참조.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from uuid import UUID
from typing import Optional


@dataclass
class UserBehaviorFeatures:
    """
    사용자 1명에 대해 24시간 슬라이딩 윈도우 기준으로 추출하는 피처.
    PostgreSQL daily_user_profiles 테이블에 저장.
    """
    tenant_id: str
    user: str
    date: str  # YYYY-MM-DD

    # 시간 패턴
    login_hour_mean: float = 0.0
    login_hour_std: float = 0.0
    login_count: int = 0
    off_hours_login_count: int = 0  # 22시~06시

    # 지리 패턴
    unique_source_ips: int = 0
    unique_countries: int = 0
    new_ip_ratio: float = 0.0

    # 행동 패턴
    failed_login_count: int = 0
    success_after_failure: int = 0
    commands_executed: int = 0
    sudo_commands: int = 0
    files_accessed: int = 0

    # 세션 패턴
    session_duration_mean: float = 0.0
    concurrent_sessions: int = 0

    def to_feature_vector(self) -> list[float]:
        """모델 입력용 피처 벡터"""
        return [
            self.login_hour_mean,
            self.login_hour_std,
            float(self.login_count),
            float(self.off_hours_login_count),
            float(self.unique_source_ips),
            float(self.unique_countries),
            self.new_ip_ratio,
            float(self.failed_login_count),
            float(self.success_after_failure),
            float(self.commands_executed),
            float(self.sudo_commands),
            float(self.files_accessed),
            self.session_duration_mean,
            float(self.concurrent_sessions),
        ]


async def extract_daily_profile_from_db(
    tenant_id: str, user: str, target_date: str
) -> "UserBehaviorFeatures":
    """signals 테이블에서 하루치 사용자 행동 집계."""
    from app.db.connection import get_session
    from sqlalchemy import text
    import math

    async with get_session() as session:
        # 로그인 이벤트 집계
        result = await session.execute(text("""
            SELECT
                AVG(EXTRACT(HOUR FROM created_at)) AS login_hour_mean,
                STDDEV(EXTRACT(HOUR FROM created_at)) AS login_hour_std,
                COUNT(*) FILTER (WHERE event_type IN ('ssh_login_failed','login_failed')) AS failed_count,
                COUNT(*) FILTER (WHERE event_type IN ('ssh_login_success','login_success')) AS success_count,
                COUNT(*) FILTER (WHERE EXTRACT(HOUR FROM created_at) >= 22 OR EXTRACT(HOUR FROM created_at) < 6) AS off_hours_count,
                COUNT(DISTINCT metadata->>'source_ip') AS unique_ips
            FROM signals
            WHERE tenant_id = :tenant_id
              AND metadata->>'user' = :user
              AND created_at::date = :target_date::date
        """), {"tenant_id": tenant_id, "user": user, "target_date": target_date})
        row = result.fetchone()

        # AUTH-004 (실패 후 성공) 집계
        saf_result = await session.execute(text("""
            SELECT COUNT(*) AS count FROM signals
            WHERE tenant_id = :tenant_id
              AND rule_id = 'AUTH-004'
              AND metadata->>'user' = :user
              AND created_at::date = :target_date::date
        """), {"tenant_id": tenant_id, "user": user, "target_date": target_date})
        saf_row = saf_result.fetchone()

        # 알려진 IP 비율 계산
        all_ips_result = await session.execute(text("""
            SELECT DISTINCT metadata->>'source_ip' AS ip FROM signals
            WHERE tenant_id = :tenant_id AND metadata->>'user' = :user
              AND created_at::date = :target_date::date
              AND metadata->>'source_ip' IS NOT NULL
        """), {"tenant_id": tenant_id, "user": user, "target_date": target_date})
        all_ips = [r.ip for r in all_ips_result.fetchall() if r.ip]

        known_ips_result = await session.execute(text("""
            SELECT ip FROM known_ips WHERE tenant_id = :tenant_id
        """), {"tenant_id": tenant_id})
        known_ips = {r.ip for r in known_ips_result.fetchall()}
        new_ip_count = sum(1 for ip in all_ips if ip not in known_ips)
        new_ip_ratio = new_ip_count / len(all_ips) if all_ips else 0.0

    if not row:
        return UserBehaviorFeatures(tenant_id=tenant_id, user=user, date=target_date)

    return UserBehaviorFeatures(
        tenant_id=tenant_id,
        user=user,
        date=target_date,
        login_hour_mean=float(row.login_hour_mean or 0),
        login_hour_std=float(row.login_hour_std or 0),
        login_count=int((row.failed_count or 0) + (row.success_count or 0)),
        off_hours_login_count=int(row.off_hours_count or 0),
        unique_source_ips=int(row.unique_ips or 0),
        unique_countries=0,  # GeoIP 연동 필요
        new_ip_ratio=new_ip_ratio,
        failed_login_count=int(row.failed_count or 0),
        success_after_failure=int(saf_row.count if saf_row else 0),
        commands_executed=0,
        sudo_commands=0,
        files_accessed=0,
        session_duration_mean=0.0,
        concurrent_sessions=0,
    )


async def aggregate_daily_profiles(tenant_id: str, target_date: str) -> list["UserBehaviorFeatures"]:
    """테넌트의 모든 사용자 daily profile 일괄 집계."""
    from app.db.connection import get_session
    from sqlalchemy import text

    async with get_session() as session:
        result = await session.execute(text("""
            SELECT DISTINCT metadata->>'user' AS user_account
            FROM signals
            WHERE tenant_id = :tenant_id
              AND created_at::date = :target_date::date
              AND metadata->>'user' IS NOT NULL
        """), {"tenant_id": tenant_id, "target_date": target_date})
        users = [r.user_account for r in result.fetchall() if r.user_account]

    profiles = []
    for user in users:
        try:
            profile = await extract_daily_profile_from_db(tenant_id, user, target_date)
            profiles.append(profile)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Profile extraction failed for {user}: {e}")
    return profiles


async def save_daily_profile(profile: "UserBehaviorFeatures") -> None:
    """집계된 프로파일을 daily_user_profiles 테이블에 upsert."""
    from app.db.connection import get_session
    from sqlalchemy import text

    async with get_session() as session:
        await session.execute(text("""
            INSERT INTO daily_user_profiles (
                tenant_id, user_account, profile_date,
                login_hour_mean, login_hour_std, login_count,
                off_hours_login_count, unique_source_ips, unique_countries,
                new_ip_ratio, failed_login_count, success_after_failure,
                commands_executed, sudo_commands, files_accessed,
                session_duration_mean, concurrent_sessions
            ) VALUES (
                :tenant_id, :user, :date,
                :lhm, :lhs, :lc,
                :ohl, :uis, :uc,
                :nir, :flc, :saf,
                :ce, :sc, :fa,
                :sdm, :cs
            )
            ON CONFLICT (tenant_id, user_account, profile_date) DO UPDATE SET
                login_hour_mean = EXCLUDED.login_hour_mean,
                login_count = EXCLUDED.login_count,
                failed_login_count = EXCLUDED.failed_login_count,
                unique_source_ips = EXCLUDED.unique_source_ips,
                new_ip_ratio = EXCLUDED.new_ip_ratio,
                computed_at = NOW()
        """), {
            "tenant_id": profile.tenant_id, "user": profile.user, "date": profile.date,
            "lhm": profile.login_hour_mean, "lhs": profile.login_hour_std, "lc": profile.login_count,
            "ohl": profile.off_hours_login_count, "uis": profile.unique_source_ips, "uc": profile.unique_countries,
            "nir": profile.new_ip_ratio, "flc": profile.failed_login_count, "saf": profile.success_after_failure,
            "ce": profile.commands_executed, "sc": profile.sudo_commands, "fa": profile.files_accessed,
            "sdm": profile.session_duration_mean, "cs": profile.concurrent_sessions,
        })
        await session.commit()
