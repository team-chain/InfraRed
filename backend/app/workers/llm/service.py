"""LLM analysis service shared by the API and worker."""
from __future__ import annotations

from app.models.llm import LLMResult
from app.config import get_settings
from app.redis_kv.client import get_redis
from app.workers.llm.providers import get_provider, build_cache_key


async def analyze_contract_with_cache(
    contract: dict,
    *,
    refresh: bool = False,
    force_static: bool = False,
) -> LLMResult:
    """LLM 분석 실행 with 캐시.

    Phase 3-B: evidence hash 포함 캐시 키로 캐시 오염 방지.
    Phase 3-A: Provider 인터페이스로 Bedrock/Anthropic 교체 가능.
    """
    settings = get_settings()
    redis = get_redis()

    # Phase 3-B: evidence hash 포함 캐시 키 (rule+severity만이 아님)
    cache_key = build_cache_key(contract)

    if not refresh:
        cached = await redis.get(cache_key)
        if cached:
            return LLMResult.model_validate_json(cached).model_copy(update={"cached": True})

    if force_static:
        from app.workers.llm.providers import StaticProvider  # noqa: PLC0415
        provider = StaticProvider()
    else:
        provider = get_provider()

    result = await provider.analyze(contract)
    await redis.set(cache_key, result.model_dump_json(), ex=settings.llm_cache_ttl_seconds)
    return result
