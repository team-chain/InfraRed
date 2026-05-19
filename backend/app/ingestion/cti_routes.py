"""CTI 수동 조회 API (설계서 v3 §11.1).

엔드포인트:
  GET  /api/v1/cti/ip/{ip}          — IP 위협 인텔리전스 조회 (OTX + Redis 캐시)
  DELETE /api/v1/cti/ip/{ip}/cache  — 캐시 강제 만료 (재조회 강제)

대시보드에서 분석가가 의심 IP를 수동으로 조회할 때 사용.
OTX 클라이언트는 이미 구현된 enrichment/otx.py를 재사용.
권한: analyst 이상
"""
from __future__ import annotations

import ipaddress
import json
import logging

from fastapi import APIRouter, Depends, HTTPException

from app.config import get_settings
from app.iam.rbac_v2 import require_role
from app.redis_kv.client import get_redis
from app.workers.enrichment.otx import OTXClient

router = APIRouter(prefix="/api/v1/cti", tags=["cti"])
log = logging.getLogger(__name__)

settings = get_settings()

# ─── 유효한 공인 IP 검증 ────────────────────────────────────────────────────

def _validate_public_ip(ip: str) -> str:
    """IP 형식 검증 + 사설/루프백 IP 거부."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"유효하지 않은 IP 형식: {ip}")

    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        raise HTTPException(
            status_code=400,
            detail="사설 IP / 루프백 / 링크-로컬 주소는 CTI 조회 대상이 아닙니다",
        )
    return ip


# ─── GET /api/v1/cti/ip/{ip} ────────────────────────────────────────────────

@router.get("/ip/{ip}")
async def lookup_ip_threat_intel(
    ip: str,
    claims: dict = Depends(require_role("analyst")),
    redis=Depends(get_redis),
) -> dict:
    """IP 위협 인텔리전스 수동 조회.

    1. Redis 캐시 확인 (캐시 키: cti:otx:ip:{ip})
    2. 캐시 미스 → OTX API 실시간 조회 (3초 타임아웃)
    3. 결과 반환 (cache_hit 필드로 출처 표시)

    응답 예시:
    {
      "ip": "45.33.100.1",
      "is_known_malicious": true,
      "pulse_count": 7,
      "abuse_score": 70,
      "country": "US",
      "asn": "AS63949",
      "is_tor_exit_node": false,
      "tags": ["otx-threat"],
      "cache_hit": false,
      "lookup_failed": false
    }
    """
    validated_ip = _validate_public_ip(ip)

    # 캐시에서 직접 조회 (OTXClient 내부 캐시 구조 재사용)
    cache_key = f"cti:otx:ip:{validated_ip}"
    cache_hit = False
    cached_raw = await redis.get(cache_key)

    if cached_raw:
        try:
            cached_data = json.loads(cached_raw)
            return {
                "ip": validated_ip,
                **cached_data,
                "cache_hit": True,
                "lookup_failed": False,
            }
        except Exception:
            pass  # 캐시 파싱 실패 시 OTX 재조회

    # OTX 실시간 조회
    otx_api_key = settings.otx_api_key if hasattr(settings, "otx_api_key") else ""
    if not otx_api_key:
        log.warning("OTX_API_KEY 미설정 — CTI 조회 불가")
        return {
            "ip": validated_ip,
            "is_known_malicious": False,
            "pulse_count": 0,
            "abuse_score": 0,
            "country": None,
            "asn": None,
            "is_tor_exit_node": False,
            "tags": [],
            "cache_hit": False,
            "lookup_failed": True,
            "error": "OTX API 키가 설정되지 않았습니다. SSM Parameter /infrared/otx-api-key를 확인하세요.",
        }

    try:
        client = OTXClient(api_key=otx_api_key, redis=redis)
        result = await client.check_ip(validated_ip)

        return {
            "ip": validated_ip,
            "is_known_malicious": (result.abuse_score or 0) > 0,
            "pulse_count": (result.abuse_score or 0) // 10,  # abuse_score에서 역산
            "abuse_score": result.abuse_score or 0,
            "country": result.country,
            "asn": None,  # OTXClient 응답에서 asn은 note에 포함
            "is_tor_exit_node": "tor" in (result.note or "").lower(),
            "tags": result.tags or [],
            "note": result.note,
            "cache_hit": cache_hit,
            "lookup_failed": False,
        }
    except Exception as exc:
        log.warning("OTX lookup failed for %s: %s", validated_ip, exc)
        return {
            "ip": validated_ip,
            "is_known_malicious": False,
            "pulse_count": 0,
            "abuse_score": 0,
            "country": None,
            "asn": None,
            "is_tor_exit_node": False,
            "tags": [],
            "cache_hit": False,
            "lookup_failed": True,
            "error": "OTX 조회 중 오류가 발생했습니다. 잠시 후 다시 시도하세요.",
        }


# ─── DELETE /api/v1/cti/ip/{ip}/cache ───────────────────────────────────────

@router.delete("/ip/{ip}/cache", status_code=200)
async def invalidate_cti_cache(
    ip: str,
    claims: dict = Depends(require_role("security_manager")),
    redis=Depends(get_redis),
) -> dict:
    """Redis CTI 캐시 강제 만료.

    다음 조회 시 OTX API를 다시 호출하여 최신 위협 정보를 반영.
    권한: security_manager 이상 (캐시 조작이므로 analyst 이상의 권한 필요)
    """
    validated_ip = _validate_public_ip(ip)
    cache_key = f"cti:otx:ip:{validated_ip}"

    deleted = await redis.delete(cache_key)
    return {
        "ip": validated_ip,
        "cache_invalidated": deleted > 0,
        "message": (
            f"{validated_ip} 캐시가 만료되었습니다. 다음 조회 시 OTX에서 재조회합니다."
            if deleted > 0
            else f"{validated_ip}에 대한 캐시가 존재하지 않습니다."
        ),
    }
