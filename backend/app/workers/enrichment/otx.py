"""AlienVault OTX CTI 클라이언트 — v3.0 설계서 Section 5."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import aiohttp
from redis.asyncio import Redis

from app.models.incident import CtiEnrichment

log = logging.getLogger(__name__)


class OTXClient:
    BASE_URL = "https://otx.alienvault.com/api/v1"
    CACHE_TTL = 3600          # 알려진 악성 IP: 1시간
    NEGATIVE_CACHE_TTL = 300  # 정상 IP: 5분

    def __init__(self, api_key: str, redis: Redis):
        self.api_key = api_key
        self.redis = redis

    async def check_ip(self, ip: str) -> CtiEnrichment:
        cache_key = f"cti:otx:ip:{ip}"
        try:
            cached = await self.redis.get(cache_key)
            if cached:
                data = json.loads(cached)
                return CtiEnrichment(**data)
        except Exception:
            pass

        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.get(
                    f"{self.BASE_URL}/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": self.api_key},
                    timeout=aiohttp.ClientTimeout(total=3),
                )
                if resp.status != 200:
                    return CtiEnrichment(note=f"OTX returned {resp.status}")

                data = await resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                is_malicious = pulse_count > 0

                result = CtiEnrichment(
                    abuse_score=min(pulse_count * 10, 100),
                    country=data.get("country_name", None),
                    tags=["otx-threat"] if is_malicious else [],
                    sources=["alienvault-otx"],
                    note=f"pulse_count={pulse_count}, asn={data.get('asn', '')}",
                )

                ttl = self.CACHE_TTL if is_malicious else self.NEGATIVE_CACHE_TTL
                await self.redis.setex(cache_key, ttl, json.dumps({
                    "abuse_score": result.abuse_score,
                    "country": result.country,
                    "tags": result.tags,
                    "sources": result.sources,
                    "note": result.note,
                }))
                return result

        except asyncio.TimeoutError:
            return CtiEnrichment(note="OTX timeout — CTI skipped", sources=[])
        except Exception as exc:
            log.warning("otx_lookup_failed ip=%s error=%s", ip, exc)
            return CtiEnrichment(note=f"OTX error: {exc}", sources=[])
