"""CISA Known Exploited Vulnerabilities (KEV) 카탈로그 클라이언트 — v7.0."""
from __future__ import annotations

import asyncio
import json
import logging

import aiohttp

log = logging.getLogger(__name__)

# Redis TTL 24시간
KEV_CACHE_TTL = 86400
KEV_CACHE_KEY = "cisa:kev:catalog"


class CISAKEVClient:
    """CISA Known Exploited Vulnerabilities 카탈로그 조회.

    KEV 카탈로그는 CVE 목록이므로 IP 직접 매칭은 불가능하지만,
    구조를 완성해 향후 IP-to-CVE 연관 데이터 소스와 연동 가능하도록 한다.
    """

    CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, redis=None):
        self.redis = redis

    async def _fetch_catalog(self) -> list[dict]:
        """KEV 카탈로그를 원격에서 가져오고 Redis에 캐시한다."""
        if self.redis:
            try:
                cached = await self.redis.get(KEV_CACHE_KEY)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.get(
                    self.CATALOG_URL,
                    timeout=aiohttp.ClientTimeout(total=15),
                )
                if resp.status != 200:
                    log.warning("CISA KEV fetch failed: HTTP %d", resp.status)
                    return []

                data = await resp.json(content_type=None)
                vulnerabilities: list[dict] = data.get("vulnerabilities", [])

                if self.redis:
                    try:
                        await self.redis.setex(
                            KEV_CACHE_KEY,
                            KEV_CACHE_TTL,
                            json.dumps(vulnerabilities),
                        )
                    except Exception as cache_exc:
                        log.warning("KEV cache write failed: %s", cache_exc)

                return vulnerabilities

        except asyncio.TimeoutError:
            log.warning("CISA KEV catalog fetch timed out")
            return []
        except Exception as exc:
            log.warning("CISA KEV catalog fetch error: %s", exc)
            return []

    async def is_ip_associated(self, ip: str) -> bool:
        """IP가 KEV 카탈로그의 CVE와 연관되어 있는지 확인.

        KEV는 CVE 목록이므로 직접 IP 매칭은 불가능하다.
        현재는 항상 False를 반환하며, 향후 IP-to-CVE 매핑 데이터와 연동 시 활용된다.
        """
        # KEV는 CVE 기반이므로 IP 직접 연관은 없음.
        # 실제 구현에서는 NVD/Shodan 등 외부 데이터와 연관 가능.
        return False

    async def get_kev_count(self) -> int:
        """현재 KEV 카탈로그의 총 CVE 수를 반환한다."""
        vulnerabilities = await self._fetch_catalog()
        return len(vulnerabilities)

    async def get_recent_kevs(self, limit: int = 10) -> list[dict]:
        """최근 추가된 KEV 항목 목록 반환."""
        vulnerabilities = await self._fetch_catalog()
        # dateAdded 기준 정렬 (내림차순)
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: v.get("dateAdded", ""),
            reverse=True,
        )
        return sorted_vulns[:limit]

    async def is_cve_in_kev(self, cve_id: str) -> bool:
        """특정 CVE ID가 KEV 카탈로그에 포함되어 있는지 확인."""
        vulnerabilities = await self._fetch_catalog()
        for vuln in vulnerabilities:
            if vuln.get("cveID", "").upper() == cve_id.upper():
                return True
        return False
