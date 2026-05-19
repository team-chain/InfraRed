"""TRAVEL-001 불가능한 이동 탐지 — v8.0 설계서

역할:
  동일 사용자의 연속된 로그인 이벤트 간 이동 속도를 계산하여
  물리적으로 불가능한 이동(Impossible Travel)을 탐지.

알고리즘:
  Haversine 공식으로 두 지점 간 거리(km) 계산.
  이동 시간(시간) = (현재 로그인 시간 - 이전 로그인 시간) / 3600
  이동 속도(km/h) = 거리 / 이동 시간
  임계값: 900km/h 초과 시 TRAVEL-001 발생

MITRE ATT&CK:
  T1078 — Valid Accounts (계정 탈취 후 원격 접속)

DB 테이블:
  login_location_history (migrate_v8_security.sql에서 생성)
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("infrared.travel_detector")

# 불가능한 이동 속도 임계값 (km/h)
# 가장 빠른 여객기 속도 약 900km/h 초과 시 물리적으로 불가능한 이동
IMPOSSIBLE_TRAVEL_SPEED_KMH = 900.0

# 최소 거리 임계값 (km): 너무 짧은 이동은 무시 (같은 도시/국가 내 VPN 전환 등)
# 설계서 §1.2: 500km — 동일 국가 내 VPN 우회 오탐 방지
MIN_DISTANCE_KM = 500.0

# 지구 반경 (km)
_EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Haversine 공식으로 두 위경도 좌표 간 거리(km)를 계산.

    Args:
      lat1, lon1: 첫 번째 위치 (도 단위)
      lat2, lon2: 두 번째 위치 (도 단위)

    Returns:
      두 지점 간 거리 (km)
    """
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return _EARTH_RADIUS_KM * c


@dataclass
class LoginLocation:
    """로그인 위치 정보."""
    user_id: str
    tenant_id: str
    ip_address: str
    latitude: float
    longitude: float
    country: str
    city: str
    logged_at: datetime
    login_event_id: str


@dataclass
class TravelCheckResult:
    """이동 속도 검사 결과."""
    is_impossible: bool
    distance_km: float
    elapsed_hours: float
    speed_kmh: float
    prev_location: LoginLocation
    curr_location: LoginLocation
    message: str


class ImpossibleTravelDetector:
    """
    사용자별 로그인 위치 이력을 기반으로 불가능한 이동을 탐지.

    사용법:
      detector = ImpossibleTravelDetector(db_session)
      result = await detector.check(login_event)
      if result and result.is_impossible:
          # TRAVEL-001 인시던트 생성
    """

    def __init__(
        self,
        speed_threshold_kmh: float = IMPOSSIBLE_TRAVEL_SPEED_KMH,
        min_distance_km: float = MIN_DISTANCE_KM,
    ) -> None:
        self.speed_threshold_kmh = speed_threshold_kmh
        self.min_distance_km = min_distance_km

    def check_travel(
        self,
        prev: LoginLocation,
        curr: LoginLocation,
    ) -> TravelCheckResult:
        """
        두 로그인 이벤트 간 이동 속도를 계산하여 불가능한 이동 여부를 반환.
        """
        distance_km = haversine_km(
            prev.latitude, prev.longitude,
            curr.latitude, curr.longitude,
        )

        # 시간 차이 계산 (시간 단위)
        time_diff = curr.logged_at - prev.logged_at
        elapsed_hours = time_diff.total_seconds() / 3600.0

        if elapsed_hours <= 0:
            # 동시 로그인 또는 시간 역전 (분산 환경에서 발생 가능)
            speed_kmh = float("inf")
            is_impossible = distance_km > self.min_distance_km
        else:
            speed_kmh = distance_km / elapsed_hours
            is_impossible = (
                speed_kmh > self.speed_threshold_kmh
                and distance_km > self.min_distance_km
            )

        if is_impossible:
            message = (
                f"불가능한 이동 감지: {prev.city}({prev.country}) → "
                f"{curr.city}({curr.country}), "
                f"거리 {distance_km:.0f}km, "
                f"경과 {elapsed_hours * 60:.1f}분, "
                f"속도 {speed_kmh:.0f}km/h (임계값 {self.speed_threshold_kmh}km/h)"
            )
            log.warning(
                "impossible_travel_detected user=%s %s",
                curr.user_id, message,
            )
        else:
            message = (
                f"정상 이동: {prev.city} → {curr.city}, "
                f"{distance_km:.0f}km, {speed_kmh:.0f}km/h"
            )

        return TravelCheckResult(
            is_impossible=is_impossible,
            distance_km=distance_km,
            elapsed_hours=elapsed_hours,
            speed_kmh=speed_kmh,
            prev_location=prev,
            curr_location=curr,
            message=message,
        )

    def build_detection_event(
        self,
        result: TravelCheckResult,
        tenant_id: str,
        agent_id: str,
    ) -> dict[str, Any]:
        """탐지 결과를 표준 이벤트 형식으로 변환."""
        return {
            "rule_id": "TRAVEL-001",
            "event_type": "impossible_travel",
            "mitre_technique": "T1078",
            "severity": "high",
            "confidence": 0.85,
            "description": result.message,
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "user_id": result.curr_location.user_id,
            "details": {
                "distance_km": round(result.distance_km, 2),
                "elapsed_hours": round(result.elapsed_hours, 4),
                "speed_kmh": round(result.speed_kmh, 2),
                "threshold_kmh": self.speed_threshold_kmh,
                "prev_login": {
                    "ip": result.prev_location.ip_address,
                    "country": result.prev_location.country,
                    "city": result.prev_location.city,
                    "lat": result.prev_location.latitude,
                    "lon": result.prev_location.longitude,
                    "logged_at": result.prev_location.logged_at.isoformat(),
                    "event_id": result.prev_location.login_event_id,
                },
                "curr_login": {
                    "ip": result.curr_location.ip_address,
                    "country": result.curr_location.country,
                    "city": result.curr_location.city,
                    "lat": result.curr_location.latitude,
                    "lon": result.curr_location.longitude,
                    "logged_at": result.curr_location.logged_at.isoformat(),
                    "event_id": result.curr_location.login_event_id,
                },
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# DB 연동 헬퍼 (SQLAlchemy async)
# ─────────────────────────────────────────────────────────────────────────────

async def get_last_login_location(
    db,
    user_id: str,
    tenant_id: str,
) -> Optional[LoginLocation]:
    """
    login_location_history 테이블에서 해당 사용자의 마지막 로그인 위치 조회.

    Args:
      db: SQLAlchemy AsyncSession
      user_id: 사용자 ID
      tenant_id: 테넌트 ID

    Returns:
      LoginLocation 또는 None (이력 없음)
    """
    from sqlalchemy import text
    query = text("""
        SELECT user_id, tenant_id, ip_address,
               latitude, longitude, country, city,
               logged_at, login_event_id
        FROM login_location_history
        WHERE user_id = :user_id
          AND tenant_id = :tenant_id
        ORDER BY logged_at DESC
        LIMIT 1
    """)
    try:
        result = await db.execute(query, {"user_id": user_id, "tenant_id": tenant_id})
        row = result.fetchone()
        if row is None:
            return None
        return LoginLocation(
            user_id=row.user_id,
            tenant_id=row.tenant_id,
            ip_address=row.ip_address,
            latitude=float(row.latitude),
            longitude=float(row.longitude),
            country=row.country or "",
            city=row.city or "",
            logged_at=row.logged_at if row.logged_at.tzinfo else
                      row.logged_at.replace(tzinfo=timezone.utc),
            login_event_id=row.login_event_id or "",
        )
    except Exception:
        log.exception("get_last_login_location_failed user=%s", user_id)
        return None


async def save_login_location(
    db,
    location: LoginLocation,
) -> None:
    """
    로그인 위치를 login_location_history 테이블에 저장.
    """
    from sqlalchemy import text
    query = text("""
        INSERT INTO login_location_history
            (user_id, tenant_id, ip_address, latitude, longitude,
             country, city, logged_at, login_event_id)
        VALUES
            (:user_id, :tenant_id, :ip_address, :latitude, :longitude,
             :country, :city, :logged_at, :login_event_id)
    """)
    try:
        await db.execute(query, {
            "user_id": location.user_id,
            "tenant_id": location.tenant_id,
            "ip_address": location.ip_address,
            "latitude": location.latitude,
            "longitude": location.longitude,
            "country": location.country,
            "city": location.city,
            "logged_at": location.logged_at,
            "login_event_id": location.login_event_id,
        })
        await db.commit()
    except Exception:
        log.exception("save_login_location_failed user=%s", location.user_id)
        await db.rollback()
