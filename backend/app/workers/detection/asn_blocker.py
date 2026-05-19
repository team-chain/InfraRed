"""ASN 기반 IP 차단 모듈 — v3 정책 매트릭스 Credential Stuffing / Password Spraying 대응.

ASN (Autonomous System Number) 조회:
  1. ipapi.co API (무료 1000회/일)
  2. ipwhois 라이브러리 (설치된 경우)
  3. 로컬 캐시 (Redis, TTL 24시간)

차단 정책:
  - ASN이 공격 출처로 반복 탐지되면 해당 ASN 전체를 Redis Denylist에 등록
  - 이후 동일 ASN IP는 403 즉시 차단
  - 관리자가 /api/v1/asn-blocks 엔드포인트로 조회/해제 가능
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

# Redis 키 접두사
_ASN_CACHE_PREFIX = "asn:info:"        # IP → ASN 정보 캐시
_ASN_BLOCK_PREFIX = "asn:block:"       # 차단된 ASN 목록
_ASN_HIT_PREFIX = "asn:hits:"          # ASN 별 탐지 횟수

# TTL 설정
_ASN_CACHE_TTL = 60 * 60 * 24          # 24시간
_ASN_BLOCK_TTL = 60 * 60 * 24 * 7     # 7일 (자동 만료)
_ASN_HIT_TTL = 60 * 60 * 24           # 24시간 내 집계

# 자동 차단 임계값: 24시간 내 동일 ASN에서 N회 이상 탐지 시 차단
AUTO_BLOCK_THRESHOLD = 10


# ------------------------------------------------------------------ #
# Redis 클라이언트 (공유)
# ------------------------------------------------------------------ #

_redis_client = None


async def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis.asyncio as aioredis  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        client = aioredis.from_url(url, encoding="utf-8", decode_responses=True,
                                   socket_connect_timeout=2, socket_timeout=2)
        await client.ping()
        _redis_client = client
        return client
    except Exception as exc:
        log.debug("asn_blocker: Redis 연결 실패: %s", exc)
        return None


# ------------------------------------------------------------------ #
# ASN 조회
# ------------------------------------------------------------------ #

async def _fetch_asn_from_api(ip: str) -> Optional[dict[str, Any]]:
    """ipapi.co에서 IP의 ASN 정보를 조회한다."""
    try:
        import asyncio  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415
        import json  # noqa: PLC0415

        def _sync_fetch():
            url = f"https://ipapi.co/{ip}/json/"
            with urllib.request.urlopen(url, timeout=3) as resp:
                return json.loads(resp.read().decode())

        data = await asyncio.to_thread(_sync_fetch)
        return {
            "asn": data.get("asn", ""),
            "org": data.get("org", ""),
            "country_code": data.get("country_code", ""),
        }
    except Exception as exc:
        log.debug("ipapi.co 조회 실패 ip=%s: %s", ip, exc)
        return None


async def _fetch_asn_ipwhois(ip: str) -> Optional[dict[str, Any]]:
    """ipwhois 라이브러리로 ASN 조회 (ipapi.co 실패 시 폴백)."""
    try:
        import asyncio  # noqa: PLC0415
        from ipwhois import IPWhois  # noqa: PLC0415

        def _sync():
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            asn = f"AS{result.get('asn', '')}"
            return {
                "asn": asn,
                "org": result.get("asn_description", ""),
                "country_code": result.get("asn_country_code", ""),
            }

        return await asyncio.to_thread(_sync)
    except Exception as exc:
        log.debug("ipwhois 조회 실패 ip=%s: %s", ip, exc)
        return None


async def get_asn_info(ip: str) -> Optional[dict[str, Any]]:
    """IP의 ASN 정보를 반환한다 (캐시 → ipapi.co → ipwhois 순서).

    Returns:
        {"asn": "AS4134", "org": "...", "country_code": "CN"} or None
    """
    if not ip or ip.startswith(("10.", "172.16.", "192.168.", "127.")):
        return None  # 사설 IP 제외

    redis = await _get_redis()

    # 캐시 확인
    if redis:
        try:
            import json  # noqa: PLC0415
            cached = await redis.get(f"{_ASN_CACHE_PREFIX}{ip}")
            if cached:
                return json.loads(cached)
        except Exception:
            pass

    # API 조회
    info = await _fetch_asn_from_api(ip)
    if not info:
        info = await _fetch_asn_ipwhois(ip)

    # 캐시 저장
    if info and redis:
        try:
            import json  # noqa: PLC0415
            await redis.set(f"{_ASN_CACHE_PREFIX}{ip}", json.dumps(info), ex=_ASN_CACHE_TTL)
        except Exception:
            pass

    return info


# ------------------------------------------------------------------ #
# 차단 / 해제 / 조회
# ------------------------------------------------------------------ #

async def is_asn_blocked(asn: str) -> bool:
    """ASN이 현재 차단 목록에 있으면 True."""
    if not asn:
        return False
    redis = await _get_redis()
    if redis:
        try:
            return bool(await redis.exists(f"{_ASN_BLOCK_PREFIX}{asn}"))
        except Exception:
            pass
    return False


async def block_asn(
    asn: str,
    reason: str = "manual",
    ttl_seconds: int = _ASN_BLOCK_TTL,
    blocked_by: str = "system",
) -> dict:
    """ASN을 차단 목록에 추가한다."""
    if not asn:
        return {"ok": False, "error": "ASN이 비어 있습니다"}

    redis = await _get_redis()
    if not redis:
        return {"ok": False, "error": "Redis 연결 실패"}

    try:
        import json  # noqa: PLC0415
        block_data = {
            "asn": asn,
            "reason": reason,
            "blocked_by": blocked_by,
            "blocked_at": datetime.now(tz=timezone.utc).isoformat(),
            "expires_at": (datetime.now(tz=timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat(),
        }
        await redis.set(
            f"{_ASN_BLOCK_PREFIX}{asn}",
            json.dumps(block_data),
            ex=ttl_seconds,
        )
        log.warning("ASN 차단 등록: asn=%s reason=%s blocked_by=%s", asn, reason, blocked_by)
        return {"ok": True, "asn": asn, "ttl_seconds": ttl_seconds}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def unblock_asn(asn: str) -> dict:
    """ASN 차단을 해제한다."""
    redis = await _get_redis()
    if not redis:
        return {"ok": False, "error": "Redis 연결 실패"}
    try:
        deleted = await redis.delete(f"{_ASN_BLOCK_PREFIX}{asn}")
        log.info("ASN 차단 해제: asn=%s", asn)
        return {"ok": True, "deleted": deleted > 0}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def list_blocked_asns() -> list[dict]:
    """현재 차단된 ASN 목록을 반환한다."""
    redis = await _get_redis()
    if not redis:
        return []
    try:
        import json  # noqa: PLC0415
        keys = await redis.keys(f"{_ASN_BLOCK_PREFIX}*")
        result = []
        for key in keys:
            val = await redis.get(key)
            if val:
                try:
                    result.append(json.loads(val))
                except Exception:
                    pass
        return result
    except Exception as exc:
        log.warning("blocked ASN 목록 조회 실패: %s", exc)
        return []


# ------------------------------------------------------------------ #
# 자동 차단 (탐지 횟수 기반)
# ------------------------------------------------------------------ #

async def record_asn_hit(asn: str, tenant_id: str) -> int:
    """ASN 탐지 횟수를 Redis에 기록하고 현재 횟수를 반환한다."""
    if not asn:
        return 0
    redis = await _get_redis()
    if not redis:
        return 0
    try:
        key = f"{_ASN_HIT_PREFIX}{tenant_id}:{asn}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, _ASN_HIT_TTL)
        return count
    except Exception:
        return 0


async def check_and_auto_block(
    asn: str,
    tenant_id: str,
    threshold: int = AUTO_BLOCK_THRESHOLD,
) -> bool:
    """탐지 횟수가 임계값을 초과하면 자동 차단하고 True를 반환한다."""
    if not asn:
        return False
    count = await record_asn_hit(asn, tenant_id)
    if count >= threshold:
        already_blocked = await is_asn_blocked(asn)
        if not already_blocked:
            await block_asn(
                asn,
                reason=f"auto_block: {count} detections in 24h (tenant={tenant_id})",
                blocked_by="system",
            )
            log.warning(
                "ASN 자동 차단: asn=%s tenant=%s count=%d threshold=%d",
                asn, tenant_id, count, threshold,
            )
            return True
    return False


# ------------------------------------------------------------------ #
# 파이프라인 헬퍼: 탐지 시그널에 ASN 체크
# ------------------------------------------------------------------ #

async def enrich_and_check_asn(signal_dict: dict) -> dict:
    """Signal dict에 ASN 정보를 추가하고, 차단 여부를 표시한다.

    Returns:
        signal_dict에 "asn", "asn_org", "asn_blocked" 필드가 추가된 dict.
    """
    source_ip = signal_dict.get("source_ip", "")
    tenant_id = signal_dict.get("tenant_id", "global")

    if not source_ip:
        return signal_dict

    signal_dict = dict(signal_dict)
    info = await get_asn_info(source_ip)

    if info:
        asn = info.get("asn", "")
        signal_dict["asn"] = asn
        signal_dict["asn_org"] = info.get("org", "")
        signal_dict["asn_country"] = info.get("country_code", "")

        if asn:
            blocked = await is_asn_blocked(asn)
            signal_dict["asn_blocked"] = blocked
            if not blocked:
                # 탐지 횟수 기록 및 자동 차단 검사
                await check_and_auto_block(asn, tenant_id)

    return signal_dict
