"""Signal enrichment worker."""
from __future__ import annotations

import asyncio

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.models.signal import Signal
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.enrichment.provider import mock_cti_lookup


configure_logging()
log = get_logger(__name__)


async def enrich_signal(payload: str) -> dict[str, str]:
    settings = get_settings()
    redis = get_redis()
    signal = Signal.model_validate_json(payload)
    cti = mock_cti_lookup(signal.source_ip)
    if signal.source_ip:
        await redis.set(
            keys.cti_ip(signal.source_ip),
            cti.model_dump_json(),
            ex=settings.cti_cache_ttl_seconds,
        )
    return {
        "signal": signal.model_dump_json(),
        "cti": cti.model_dump_json(),
    }


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    input_stream = streams.signals_matched(settings.tenant_id)
    output_stream = streams.signals_enriched(settings.tenant_id)
    await ensure_group(redis, input_stream, streams.GROUP_ENRICHMENT)
    consumer = f"enrichment-{settings.agent_id}"
    log.info("enrichment_worker_started", stream=input_stream)

    while True:
        messages = await redis.xreadgroup(
            streams.GROUP_ENRICHMENT,
            consumer,
            {input_stream: ">"},
            count=10,
            block=5000,
        )
        if not messages:
            continue
        for _, entries in messages:
            for stream_id, fields in entries:
                try:
                    enriched = await enrich_signal(fields["payload"])
                    await redis.xadd(
                        output_stream,
                        enriched,
                        maxlen=settings.redis_stream_maxlen,
                        approximate=True,
                    )
                    await redis.xack(input_stream, streams.GROUP_ENRICHMENT, stream_id)
                    log.info("signal_enriched", stream_id=stream_id)
                except Exception as exc:  # noqa: BLE001
                    log.exception("enrichment_failed", stream_id=stream_id, error=str(exc))
                    await redis.xack(input_stream, streams.GROUP_ENRICHMENT, stream_id)


if __name__ == "__main__":
    asyncio.run(main())
