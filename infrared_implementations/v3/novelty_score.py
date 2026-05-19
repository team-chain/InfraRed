"""Novelty Score 계산 모듈.

Detection Worker 가 Signal 을 생성할 때 호출.
Redis SET 에 seen IPs / usernames 을 저장하고,
처음 보는 IP / 계정이면 novelty_score 를 높임.

설계서 v3: Signal 레벨 novelty 점수 → Correlation Worker 에서 캠페인 우선순위 계산에 사용.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from redis.asyncio import Redis

log = logging.getLogger(__name__)

# Redis 키 TTL (기본 30일)
SEEN_IP_TTL_SECONDS = 30 * 24 * 3600       # 30일
SEEN_USER_TTL_SECONDS = 30 * 24 * 3600     # 30일
SEEN_ASN_TTL_SECONDS = 7 * 24 * 3600       # 7일
SEEN_USERAGENT_TTL_SECONDS = 14 * 24 * 3600  # 14일

# Novelty score 가중치 (0~1 범위로 정규화됨)
_WEIGHT_NEW_IP = 0.35
_WEIGHT_NEW_USER = 0.25
_WEIGHT_NEW_ASN = 0.20
_WEIGHT_NEW_USERAGENT = 0.10
_WEIGHT_ODD_HOUR = 0.10  # 새벽 0~5시


def _redis_seen_ip_key(tenant_id: str) -> str:
    return f"novelty:seen_ips:{tenant_id}"


def _redis_seen_user_key(tenant_id: str) -> str:
    return f"novelty:seen_users:{tenant_id}"


def _redis_seen_asn_key(tenant_id: str) -> str:
    return f"novelty:seen_asns:{tenant_id}"


def _redis_seen_useragent_key(tenant_id: str) -> str:
    return f"novelty:seen_useragents:{tenant_id}"


# ────────────────────────────────────────────────────────────────────────────
# 핵심 로직
# ────────────────────────────────────────────────────────────────────────────

async def _is_new_and_record(
    redis: Redis,
    set_key: str,
    member: str,
    ttl_seconds: int,
) -> bool:
    """Redis SET 에 member 가 없으면 True 반환 후 추가. 있으면 False."""
    if not member:
        return False
    # SISMEMBER 로 존재 확인
    exists: int = await redis.sismember(set_key, member)
    if exists:
        return False

    # 새 멤버 추가
    await redis.sadd(set_key, member)
    # TTL 갱신 (키가 새로 만들어졌을 때만 EXPIRE 적용 — 기존 TTL 유지)
    current_ttl: int = await redis.ttl(set_key)
    if current_ttl < 0:
        await redis.expire(set_key, ttl_seconds)

    return True


def _is_odd_hour(ts: Optional[datetime]) -> bool:
    """새벽 0시 ~ 5시 59분 이면 True (UTC 기준)."""
    if ts is None:
        ts = datetime.now(timezone.utc)
    utc_ts = ts.astimezone(timezone.utc) if ts.tzinfo else ts
    return utc_ts.hour < 6


async def calculate_novelty_score(
    redis: Redis,
    *,
    tenant_id: str,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    asn: Optional[str] = None,
    user_agent: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> float:
    """
    주어진 속성들을 기반으로 Novelty Score (0.0 ~ 1.0) 계산.

    처음 보는 IP, 계정, ASN, 새벽 접근 등을 가중 합산한다.

    Args:
        redis:      Redis 비동기 클라이언트
        tenant_id:  테넌트 ID
        source_ip:  소스 IP (Optional)
        username:   인증 사용자 이름 (Optional)
        asn:        ASN 번호 (예: "AS4134") (Optional)
        user_agent: HTTP User-Agent (Optional)
        timestamp:  이벤트 발생 시각 (Optional, 기본값 NOW())

    Returns:
        float: 0.0 (전혀 새롭지 않음) ~ 1.0 (완전히 새로운 조합)
    """
    score = 0.0

    try:
        # 새 IP 여부
        if source_ip:
            is_new_ip = await _is_new_and_record(
                redis,
                _redis_seen_ip_key(tenant_id),
                source_ip,
                SEEN_IP_TTL_SECONDS,
            )
            if is_new_ip:
                score += _WEIGHT_NEW_IP
                log.info(
                    "novelty_new_ip tenant=%s ip=%s score_delta=%.2f",
                    tenant_id, source_ip, _WEIGHT_NEW_IP,
                )

        # 새 사용자 여부
        if username:
            is_new_user = await _is_new_and_record(
                redis,
                _redis_seen_user_key(tenant_id),
                username,
                SEEN_USER_TTL_SECONDS,
            )
            if is_new_user:
                score += _WEIGHT_NEW_USER
                log.info(
                    "novelty_new_user tenant=%s user=%s score_delta=%.2f",
                    tenant_id, username, _WEIGHT_NEW_USER,
                )

        # 새 ASN 여부
        if asn:
            is_new_asn = await _is_new_and_record(
                redis,
                _redis_seen_asn_key(tenant_id),
                asn,
                SEEN_ASN_TTL_SECONDS,
            )
            if is_new_asn:
                score += _WEIGHT_NEW_ASN
                log.info(
                    "novelty_new_asn tenant=%s asn=%s score_delta=%.2f",
                    tenant_id, asn, _WEIGHT_NEW_ASN,
                )

        # 새 User-Agent 여부
        if user_agent:
            # User-Agent 는 앞 100자만 사용 (노이즈 제거)
            ua_key = user_agent[:100]
            is_new_ua = await _is_new_and_record(
                redis,
                _redis_seen_useragent_key(tenant_id),
                ua_key,
                SEEN_USERAGENT_TTL_SECONDS,
            )
            if is_new_ua:
                score += _WEIGHT_NEW_USERAGENT

        # 비정상 시간대 접근
        if _is_odd_hour(timestamp):
            score += _WEIGHT_ODD_HOUR

    except Exception as exc:
        log.warning(
            "novelty_score_calculation_failed tenant=%s error=%s returning_0",
            tenant_id, exc,
        )
        return 0.0

    # 0.0 ~ 1.0 클램프
    final_score = min(round(score, 3), 1.0)
    log.debug(
        "novelty_score_calculated tenant=%s ip=%s score=%.3f",
        tenant_id, source_ip, final_score,
    )
    return final_score


async def enrich_signal_with_novelty(
    redis: Redis,
    signal_dict: dict,
) -> dict:
    """
    Signal dict 에 novelty_score 필드를 추가해 반환.
    Detection Worker 파이프라인에서 Signal 생성 직후 호출.
    """
    tenant_id: str = signal_dict.get("tenant_id", "global")
    source_ip: Optional[str] = signal_dict.get("source_ip")
    username: Optional[str] = signal_dict.get("username") or signal_dict.get("user")
    asn: Optional[str] = signal_dict.get("asn")
    user_agent: Optional[str] = signal_dict.get("user_agent")

    ts_raw = signal_dict.get("detected_at") or signal_dict.get("timestamp")
    ts: Optional[datetime] = None
    if isinstance(ts_raw, str):
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    elif isinstance(ts_raw, datetime):
        ts = ts_raw

    novelty = await calculate_novelty_score(
        redis,
        tenant_id=tenant_id,
        source_ip=source_ip,
        username=username,
        asn=asn,
        user_agent=user_agent,
        timestamp=ts,
    )

    signal_dict = dict(signal_dict)
    signal_dict["novelty_score"] = novelty
    return signal_dict


# ────────────────────────────────────────────────────────────────────────────
# 관리 유틸
# ────────────────────────────────────────────────────────────────────────────

async def reset_seen_data(redis: Redis, tenant_id: str, category: str = "all") -> dict[str, int]:
    """지정 카테고리의 seen 데이터 초기화. 테스트/관리 목적."""
    deleted = 0

    key_map = {
        "ips": _redis_seen_ip_key(tenant_id),
        "users": _redis_seen_user_key(tenant_id),
        "asns": _redis_seen_asn_key(tenant_id),
        "useragents": _redis_seen_useragent_key(tenant_id),
    }

    if category == "all":
        targets = list(key_map.values())
    elif category in key_map:
        targets = [key_map[category]]
    else:
        return {"deleted": 0}

    for key in targets:
        deleted += await redis.delete(key)

    log.warning(
        "novelty_seen_data_reset tenant=%s category=%s deleted_keys=%d",
        tenant_id, category, deleted,
    )
    return {"deleted": deleted}


async def get_seen_stats(redis: Redis, tenant_id: str) -> dict[str, int]:
    """현재 seen 데이터 크기 조회."""
    return {
        "seen_ips": await redis.scard(_redis_seen_ip_key(tenant_id)),
        "seen_users": await redis.scard(_redis_seen_user_key(tenant_id)),
        "seen_asns": await redis.scard(_redis_seen_asn_key(tenant_id)),
        "seen_useragents": await redis.scard(_redis_seen_useragent_key(tenant_id)),
    }
