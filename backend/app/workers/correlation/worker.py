"""Correlation worker that creates incidents and triggers role C."""
from __future__ import annotations

import asyncio

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import save_incident
from app.models.incident import CtiEnrichment
from app.models.signal import Signal
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.correlation.builder import build_incident


configure_logging()
log = get_logger(__name__)


async def process_enriched(signal_payload: str, cti_payload: str) -> str | None:
    settings = get_settings()
    redis = get_redis()
    signal = Signal.model_validate_json(signal_payload)
    cti = CtiEnrichment.model_validate_json(cti_payload)
    dedup_key = keys.incident_dedup(
        signal.tenant_id,
        signal.rule_id.value,
        signal.asset_id,
        signal.source_ip or "none",
        signal.username or "none",
    )
    is_new = await redis.set(dedup_key, "1", nx=True, ex=600)
    if not is_new:
        log.info("incident_duplicate_skipped", signal_id=signal.signal_id)
        return None

    incident = build_incident(signal, cti)
    await save_incident(incident)
    await redis.xadd(
        streams.incidents_new(incident.tenant_id),
        {
            "incident_id": incident.incident_id,
            "tenant_id": incident.tenant_id,
            "signal_ids": ",".join(incident.signal_ids),
        },
        maxlen=settings.redis_stream_maxlen,
        approximate=True,
    )
    return incident.incident_id


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    stream = streams.signals_enriched(settings.tenant_id)
    await ensure_group(redis, stream, streams.GROUP_CORRELATION)
    consumer = f"correlation-{settings.agent_id}"
    log.info("correlation_worker_started", stream=stream)

    while True:
        messages = await redis.xreadgroup(
            streams.GROUP_CORRELATION,
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
                    incident_id = await process_enriched(fields["signal"], fields["cti"])
                    await redis.xack(stream, streams.GROUP_CORRELATION, stream_id)
                    if incident_id:
                        log.info("incident_created", incident_id=incident_id)
                except Exception as exc:  # noqa: BLE001
                    log.exception("correlation_failed", stream_id=stream_id, error=str(exc))
                    await redis.xack(stream, streams.GROUP_CORRELATION, stream_id)


if __name__ == "__main__":
    asyncio.run(main())
