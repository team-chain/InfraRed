"""Signal enrichment worker.

Pipeline stage (B):
    matched signal (signals:matched)
        -> GeoIP lookup
        -> CTI lookup
        -> merge into a single CtiEnrichment shape
        -> emit onto signals:enriched
"""
from __future__ import annotations

import asyncio

from prometheus_client import Counter

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.models.incident import CtiEnrichment
from app.models.signal import Signal
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.dlq import reclaim_pending
from app.workers.enrichment.geoip import GeoLocation, lookup_geoip
from app.workers.enrichment.provider import mock_cti_lookup


configure_logging()
log = get_logger(__name__)


ENRICHMENT_EVENTS = Counter(
    "infrared_enrichment_events_total",
    "Outcomes of the enrichment worker.",
    ["outcome"],
)


def _merge_geo_into_cti(cti: CtiEnrichment, geo: GeoLocation) -> CtiEnrichment:
    """Merge GeoIP facts into the existing CTI enrichment.

    GeoIP fills the country, gives us an ASN tag, and records the geo source.
    The CTI lookup wins on abuse_score and threat tags; GeoIP just adds
    complementary location context for the incident view.
    """

    tags = list(cti.tags)
    if geo.asn_org:
        asn_tag = f"asn:{geo.asn_org}"
        if asn_tag not in tags:
            tags.append(asn_tag)
    if geo.is_private and "private-ip" not in tags:
        tags.append("private-ip")

    sources = list(cti.sources)
    for source in geo.sources:
        if source not in sources:
            sources.append(source)

    note_parts = [part for part in [cti.note, geo.note] if part]

    return CtiEnrichment(
        abuse_score=cti.abuse_score,
        country=cti.country or geo.country,
        tags=tags,
        sources=sources,
        note=" | ".join(note_parts) if note_parts else None,
    )


async def enrich_signal(payload: str) -> dict[str, str]:
    settings = get_settings()
    redis = get_redis()
    signal = Signal.model_validate_json(payload)
    cti = mock_cti_lookup(signal.source_ip)
    geo = lookup_geoip(signal.source_ip)
    merged = _merge_geo_into_cti(cti, geo)

    if signal.source_ip:
        await redis.set(
            keys.cti_ip(signal.source_ip),
            merged.model_dump_json(),
            ex=settings.cti_cache_ttl_seconds,
        )

    ENRICHMENT_EVENTS.labels(outcome="enriched").inc()
    return {
        "signal": signal.model_dump_json(),
        "cti": merged.model_dump_json(),
        "geo": geo.model_dump_json(),
    }


async def _handle(stream_id: str, fields: dict) -> None:
    settings = get_settings()
    redis = get_redis()
    output_stream = streams.signals_enriched(settings.tenant_id)
    enriched = await enrich_signal(fields["payload"])
    await redis.xadd(
        output_stream,
        enriched,
        maxlen=settings.redis_stream_maxlen,
        approximate=True,
    )


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    input_stream = streams.signals_matched(settings.tenant_id)
    output_stream = streams.signals_enriched(settings.tenant_id)
    await ensure_group(redis, input_stream, streams.GROUP_ENRICHMENT)
    consumer = f"enrichment-{settings.agent_id}"
    log.info("enrichment_worker_started", stream=input_stream)

    while True:
        # ── Process new messages ──────────────────────────────────────────────
        messages = await redis.xreadgroup(
            streams.GROUP_ENRICHMENT,
            consumer,
            {input_stream: ">"},
            count=10,
            block=5000,
        )
        if messages:
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
                        ENRICHMENT_EVENTS.labels(outcome="enriched").inc()
                    except Exception as exc:  # noqa: BLE001
                        # Leave in PEL for retry via XAUTOCLAIM
                        ENRICHMENT_EVENTS.labels(outcome="failed").inc()
                        log.exception("enrichment_failed", stream_id=stream_id, error=str(exc))

        # ── Reclaim & retry idle PEL messages ────────────────────────────────
        await reclaim_pending(
            redis=redis,
            stream=input_stream,
            group=streams.GROUP_ENRICHMENT,
            consumer=consumer,
            tenant_id=settings.tenant_id,
            stage="enrichment",
            idle_ms=settings.dlq_idle_seconds * 1000,
            max_retries=settings.dlq_max_retries,
            handler=_handle,
        )


if __name__ == "__main__":
    asyncio.run(main())
