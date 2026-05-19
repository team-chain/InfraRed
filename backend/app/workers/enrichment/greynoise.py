"""GreyNoise CTI 클라이언트 — v7.0 다중소스 CTI."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import aiohttp

from app.models.incident import CtiEnrichment

log = logging.getLogger(__name__)


class GreyNoiseClient:
    BASE_URL = "https://api.greynoise.io/v3/community/{ip}"
    CACHE_TTL = 3600
    NEGATIVE_CACHE_TTL = 600

    def __init__(self, api_key: str, redis=None):
        self.api_key = api_key
        self.redis = redis

    async def check_ip(self, ip: str) -> CtiEnrichment:
        """GreyNoise Community API로 IP 조회."""
        cache_key = f"cti:greynoise:ip:{ip}"

        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    data = json.loads(cached)
                    return CtiEnrichment(**data)
            except Exception:
                pass

        try:
            url = self.BASE_URL.format(ip=ip)
            async with aiohttp.ClientSession() as session:
                resp = await session.get(
                    url,
                    headers={
                        "key": self.api_key,
                        "Accept": "application/json",
                    },
                    timeout=aiohttp.ClientTimeout(total=5),
                )

                # 404 = IP not in GreyNoise dataset (neutral)
                if resp.status == 404:
                    result = CtiEnrichment(
                        abuse_score=0,
                        tags=[],
                        sources=["greynoise"],
                        note="IP not found in GreyNoise dataset",
                    )
                    if self.redis:
                        await self.redis.setex(cache_key, self.NEGATIVE_CACHE_TTL, json.dumps({
                            "abuse_score": result.abuse_score,
                            "country": result.country,
                            "tags": result.tags,
                            "sources": result.sources,
                            "note": result.note,
                        }))
                    return result

                if resp.status != 200:
                    return CtiEnrichment(
                        note=f"GreyNoise returned {resp.status}",
                        sources=["greynoise"],
                    )

                data = await resp.json()

                noise: bool = data.get("noise", False)
                riot: bool = data.get("riot", False)
                classification: str = data.get("classification", "")
                country = data.get("country_code") or None
                name = data.get("name", "")

                tags: list[str] = []
                abuse_score = 0

                if riot:
                    # Benign known service (Google, Cloudflare 등)
                    tags.append("benign-service")
                    abuse_score = 5

                elif noise:
                    # Mass internet scanner
                    tags.append("mass-scanner")
                    if classification == "malicious":
                        abuse_score = 85
                        tags.append("greynoise-malicious")
                    elif classification == "benign":
                        abuse_score = 15
                    else:
                        # unknown classification but is noise
                        abuse_score = 40

                else:
                    # Not seen by GreyNoise
                    if classification == "malicious":
                        abuse_score = 80
                    elif classification == "benign":
                        abuse_score = 10
                    else:
                        abuse_score = 0

                note_parts = []
                if name:
                    note_parts.append(f"name={name}")
                if classification:
                    note_parts.append(f"classification={classification}")
                note_parts.append(f"noise={noise}, riot={riot}")

                result = CtiEnrichment(
                    abuse_score=abuse_score,
                    country=country,
                    tags=tags,
                    sources=["greynoise"],
                    note=", ".join(note_parts),
                )

                ttl = self.CACHE_TTL if abuse_score >= 40 else self.NEGATIVE_CACHE_TTL
                if self.redis:
                    await self.redis.setex(cache_key, ttl, json.dumps({
                        "abuse_score": result.abuse_score,
                        "country": result.country,
                        "tags": result.tags,
                        "sources": result.sources,
                        "note": result.note,
                    }))
                return result

        except asyncio.TimeoutError:
            return CtiEnrichment(note="GreyNoise timeout — CTI skipped", sources=["greynoise"])
        except Exception as exc:
            log.warning("greynoise_lookup_failed ip=%s error=%s", ip, exc)
            return CtiEnrichment(note=f"GreyNoise error: {exc}", sources=["greynoise"])
