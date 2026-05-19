"""CTI provider — OTX / AbuseIPDB / GreyNoise / CISA KEV with deterministic mock fallback.

Priority / Source weights:
  - OTX:       weight=0.35
  - AbuseIPDB: weight=0.30
  - GreyNoise: weight=0.25
  - CISA KEV:  weight=0.10
  - Mock:      fallback when all API sources fail

v7.0: 다중소스 병렬 조회 + 가중 투표 충돌 해소 알고리즘
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
from typing import Optional

import httpx

from app.config import get_settings
from app.models.incident import CtiEnrichment


log = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

MOCK_COUNTRIES = ["US", "KR", "NL", "DE", "SG", "JP"]

# 소스별 가중치
_SOURCE_WEIGHTS: dict[str, float] = {
    "alienvault-otx": 0.35,
    "abuseipdb": 0.30,
    "greynoise": 0.25,
    "cisa-kev": 0.10,
    "mock-cti": 0.10,
}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _mock_cti_lookup(ip: str) -> CtiEnrichment:
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    score = digest[0] % 100
    tags: list[str] = []
    if score >= 70:
        tags.append("high-risk-ip")
    if score >= 40:
        tags.append("scanner")
    return CtiEnrichment(
        abuse_score=score,
        country=MOCK_COUNTRIES[digest[1] % len(MOCK_COUNTRIES)],
        tags=tags,
        sources=["mock-cti"],
        note="Deterministic mock CTI result (AbuseIPDB unavailable).",
    )


def _abuseipdb_lookup(ip: str, api_key: str) -> CtiEnrichment:
    """Query AbuseIPDB v2 check endpoint synchronously."""
    try:
        response = httpx.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        score = int(data.get("abuseConfidenceScore", 0))
        country = data.get("countryCode") or None
        is_tor = data.get("isTor", False)
        usage_type = data.get("usageType") or ""
        domain = data.get("domain") or ""
        total_reports = int(data.get("totalReports", 0))

        tags: list[str] = []
        if score >= 80:
            tags.append("high-risk-ip")
        if score >= 40:
            tags.append("scanner")
        if is_tor:
            tags.append("tor-exit-node")
        if "VPN" in usage_type or "Proxy" in usage_type:
            tags.append("vpn-proxy")

        note_parts = []
        if domain:
            note_parts.append(f"domain={domain}")
        if usage_type:
            note_parts.append(f"type={usage_type}")
        if total_reports:
            note_parts.append(f"reports={total_reports}")

        return CtiEnrichment(
            abuse_score=score,
            country=country,
            tags=tags,
            sources=["abuseipdb"],
            note=", ".join(note_parts) if note_parts else None,
        )
    except Exception as exc:
        log.warning("abuseipdb_lookup_failed ip=%s error=%s", ip, exc)
        return _mock_cti_lookup(ip)


async def _otx_lookup(ip: str, api_key: str) -> CtiEnrichment:
    """Query AlienVault OTX asynchronously (with Redis cache via OTXClient)."""
    from app.redis_kv.client import get_redis
    from app.workers.enrichment.otx import OTXClient
    redis = get_redis()
    client = OTXClient(api_key=api_key, redis=redis)
    return await client.check_ip(ip)


async def _greynoise_lookup(ip: str, api_key: str) -> CtiEnrichment:
    """Query GreyNoise Community API asynchronously."""
    from app.redis_kv.client import get_redis
    from app.workers.enrichment.greynoise import GreyNoiseClient
    redis = get_redis()
    client = GreyNoiseClient(api_key=api_key, redis=redis)
    return await client.check_ip(ip)


async def _cisa_kev_lookup(ip: str) -> CtiEnrichment:
    """CISA KEV 카탈로그 기반 CTI 조회 (IP 직접 매칭 불가, 구조 완성용)."""
    from app.redis_kv.client import get_redis
    from app.workers.enrichment.cisa_kev import CISAKEVClient
    redis = get_redis()
    client = CISAKEVClient(redis=redis)
    is_associated = await client.is_ip_associated(ip)
    return CtiEnrichment(
        abuse_score=90 if is_associated else 0,
        tags=["kev-associated"] if is_associated else [],
        sources=["cisa-kev"],
        note="CISA KEV association check",
    )


def _resolve_cti_conflict(results: list[CtiEnrichment]) -> CtiEnrichment:
    """가중 투표 알고리즘으로 다중 CTI 소스 결과를 병합한다.

    알고리즘:
    - 각 소스의 가중치를 사용해 abuse_score 가중 평균 계산
    - tags: 모든 소스의 합집합
    - country: 첫 번째 non-None 값 사용
    - sources: 사용된 모든 소스 목록
    - 결과에 abuse_score가 없는 소스는 합산에서 제외
    """
    if not results:
        return CtiEnrichment(note="No CTI sources available.")

    if len(results) == 1:
        return results[0]

    weighted_score_sum = 0.0
    weight_sum = 0.0
    all_tags: set[str] = set()
    all_sources: list[str] = []
    first_country: Optional[str] = None
    note_parts: list[str] = []

    for enrichment in results:
        # 소스 목록 수집
        for source in enrichment.sources:
            if source not in all_sources:
                all_sources.append(source)

            # 가중 점수 계산 (abuse_score가 있는 소스만)
            if enrichment.abuse_score is not None:
                weight = _SOURCE_WEIGHTS.get(source, 0.10)
                weighted_score_sum += enrichment.abuse_score * weight
                weight_sum += weight

        # tags 합집합
        all_tags.update(enrichment.tags)

        # 첫 번째 non-None country 사용
        if first_country is None and enrichment.country:
            first_country = enrichment.country

        # 노트 수집
        if enrichment.note:
            note_parts.append(enrichment.note)

    # 최종 abuse_score 계산
    final_score: Optional[int] = None
    if weight_sum > 0:
        final_score = int(round(weighted_score_sum / weight_sum))

    return CtiEnrichment(
        abuse_score=final_score,
        country=first_country,
        tags=sorted(all_tags),
        sources=all_sources,
        note=f"[multi-source] {'; '.join(note_parts)}" if note_parts else "[multi-source]",
    )


def mock_cti_lookup(ip: Optional[str]) -> CtiEnrichment:
    """Public interface called by the enrichment worker (sync entry point).

    Priority: otx → abuseipdb → mock
    OTX is async; when selected it is run via asyncio.run() in a thread-safe way.
    The enrichment worker is async itself, so we bridge via run_in_executor or
    a dedicated async path. Since mock_cti_lookup is called from the async worker,
    we detect the running loop and schedule accordingly.
    """
    if not ip:
        return CtiEnrichment(note="No source IP was available for CTI lookup.")

    if _is_private(ip):
        return CtiEnrichment(note="Private/loopback IP — CTI lookup skipped.")

    settings = get_settings()

    if settings.cti_provider == "otx" and settings.otx_api_key:
        # Worker is already inside an async context; run the coroutine there.
        try:
            loop = asyncio.get_running_loop()
            # We are inside an async context — caller should use mock_cti_lookup_async.
            # Fallback: run synchronously with a new event loop in a thread.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    asyncio.run,
                    _otx_lookup(ip, settings.otx_api_key),
                )
                return future.result(timeout=5)
        except RuntimeError:
            # No running loop — safe to use asyncio.run()
            return asyncio.run(_otx_lookup(ip, settings.otx_api_key))

    if settings.cti_provider == "abuseipdb" and settings.abuseipdb_api_key:
        return _abuseipdb_lookup(ip, settings.abuseipdb_api_key)

    return _mock_cti_lookup(ip)


async def mock_cti_lookup_async(ip: Optional[str]) -> CtiEnrichment:
    """Async version — v7.0: 다중소스 병렬 조회 + 가중 투표 충돌 해소.

    사용 가능한 모든 CTI 소스를 병렬로 조회하고 _resolve_cti_conflict로 결과 병합.
    소스가 없으면 deterministic mock으로 폴백.
    """
    if not ip:
        return CtiEnrichment(note="No source IP was available for CTI lookup.")

    if _is_private(ip):
        return CtiEnrichment(note="Private/loopback IP — CTI lookup skipped.")

    settings = get_settings()

    # 병렬 조회할 소스 코루틴 목록 구성
    tasks: list = []
    source_names: list[str] = []

    if settings.cti_provider == "otx" and settings.otx_api_key:
        tasks.append(_otx_lookup(ip, settings.otx_api_key))
        source_names.append("otx")

    if settings.cti_provider == "abuseipdb" and settings.abuseipdb_api_key:
        # abuseipdb는 동기 함수이므로 executor로 래핑
        loop = asyncio.get_event_loop()
        tasks.append(
            loop.run_in_executor(None, _abuseipdb_lookup, ip, settings.abuseipdb_api_key)
        )
        source_names.append("abuseipdb")

    # GreyNoise — GREYNOISE_API_KEY가 있으면 추가 (config에 없으므로 환경변수 직접 조회)
    import os
    greynoise_key = os.environ.get("GREYNOISE_API_KEY", "")
    if greynoise_key:
        tasks.append(_greynoise_lookup(ip, greynoise_key))
        source_names.append("greynoise")

    # CISA KEV — 항상 조회 (외부 API 키 불필요)
    tasks.append(_cisa_kev_lookup(ip))
    source_names.append("cisa-kev")

    if not tasks or (len(tasks) == 1 and source_names[0] == "cisa-kev"):
        # API 설정 없음 → mock fallback
        return _mock_cti_lookup(ip)

    # 모든 소스 병렬 조회
    gather_results = await asyncio.gather(*tasks, return_exceptions=True)

    # 성공한 결과만 수집
    valid_results: list[CtiEnrichment] = []
    for idx, result in enumerate(gather_results):
        if isinstance(result, Exception):
            log.warning(
                "cti_source_failed source=%s ip=%s error=%s",
                source_names[idx], ip, result,
            )
        elif isinstance(result, CtiEnrichment):
            valid_results.append(result)

    if not valid_results:
        log.warning("all_cti_sources_failed ip=%s, falling back to mock", ip)
        return _mock_cti_lookup(ip)

    # 단일 소스면 그대로, 다중 소스면 충돌 해소
    return _resolve_cti_conflict(valid_results)
