"""Incident trigger consumer for LLM analysis and alert dispatch."""
from __future__ import annotations

import asyncio

import httpx

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import save_llm_result
from app.dispatcher.service import dispatch_incident_alert
from app.redis_kv import streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.llm.bedrock import analyze_with_bedrock


configure_logging()
log = get_logger(__name__)


async def fetch_incident_contract(incident_id: str) -> dict:
    settings = get_settings()
    url = f"{settings.internal_api_base_url.rstrip('/')}/incidents/{incident_id}"
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def process_incident(incident_id: str, tenant_id: str) -> None:
    contract = await fetch_incident_contract(incident_id)
    result = await analyze_with_bedrock(contract)
    await save_llm_result(result, tenant_id=tenant_id)
    await dispatch_incident_alert(tenant_id, result)


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    stream = streams.incidents_new(settings.tenant_id)
    await ensure_group(redis, stream, streams.GROUP_LLM)
    consumer = f"llm-{settings.agent_id}"
    log.info("llm_worker_started", stream=stream)

    while True:
        messages = await redis.xreadgroup(
            streams.GROUP_LLM,
            consumer,
            {stream: ">"},
            count=10,
            block=5000,
        )
        if not messages:
            continue
        for _, entries in messages:
            for stream_id, fields in entries:
                try:
                    await process_incident(fields["incident_id"], fields["tenant_id"])
                    await redis.xack(stream, streams.GROUP_LLM, stream_id)
                    log.info("llm_result_saved", incident_id=fields["incident_id"])
                except Exception as exc:  # noqa: BLE001
                    log.exception("llm_worker_failed", stream_id=stream_id, error=str(exc))
                    await redis.xack(stream, streams.GROUP_LLM, stream_id)


if __name__ == "__main__":
    asyncio.run(main())
