"""LLM analysis service shared by the API and worker."""
from __future__ import annotations

from app.models.llm import LLMResult
from app.config import get_settings
from app.redis_kv import keys
from app.redis_kv.client import get_redis
from app.workers.llm.bedrock import analyze_with_bedrock
from app.workers.llm.playbook import summarize_with_playbook


async def analyze_contract_with_cache(
    contract: dict,
    *,
    refresh: bool = False,
    force_static: bool = False,
) -> LLMResult:
    settings = get_settings()
    incident = contract["incident"]
    cache_key = keys.llm_incident_cache(incident["incident_id"])
    redis = get_redis()

    if not refresh:
        cached = await redis.get(cache_key)
        if cached:
            return LLMResult.model_validate_json(cached).model_copy(update={"cached": True})

    result = summarize_with_playbook(contract) if force_static else await analyze_with_bedrock(contract)
    await redis.set(cache_key, result.model_dump_json(), ex=settings.llm_cache_ttl_seconds)
    return result
