"""Redis raw-envelope consumer for detection."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import save_normalized_event, save_signal
from app.models.envelope import RawEventEnvelope
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.detection.parser import parse_auth_log
from app.workers.detection.rules import evaluate_rules


configure_logging()
log = get_logger(__name__)


async def process_payload(stream_id: str, payload: str) -> None:
    settings = get_settings()
    redis = get_redis()
    envelope = RawEventEnvelope.model_validate_json(payload)
    dedup_key = keys.event_dedup(envelope.tenant_id, envelope.event_id)
    is_new = await redis.set(dedup_key, "1", nx=True, ex=settings.dedup_ttl_seconds)
    if not is_new:
        log.info("event_duplicate_skipped", event_id=envelope.event_id)
        return

    event = parse_auth_log(envelope)
    if event is None:
        log.info("event_unparsed", event_id=envelope.event_id)
        return

    await save_normalized_event(event)
    signals = await evaluate_rules(redis, event)
    for signal in signals:
        await save_signal(signal)
        await redis.xadd(
            streams.signals_matched(signal.tenant_id),
            {"payload": signal.model_dump_json()},
            maxlen=settings.redis_stream_maxlen,
            approximate=True,
        )
        log.info("signal_matched", signal_id=signal.signal_id, rule_id=signal.rule_id.value)


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    stream = streams.events_raw(settings.tenant_id)
    await ensure_group(redis, stream, streams.GROUP_DETECTION)
    consumer = f"detection-{settings.agent_id}"
    log.info("detection_worker_started", stream=stream, group=streams.GROUP_DETECTION)

    while True:
        messages = await redis.xreadgroup(
            streams.GROUP_DETECTION,
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
                    await process_payload(stream_id, fields["payload"])
                    await redis.xack(stream, streams.GROUP_DETECTION, stream_id)
                except Exception as exc:  # noqa: BLE001
                    log.exception("detection_failed", stream_id=stream_id, error=str(exc))
                    await redis.xadd(
                        streams.events_failed(settings.tenant_id),
                        {
                            "failed_at": datetime.now(timezone.utc).isoformat(),
                            "stage": "detection",
                            "stream_id": stream_id,
                            "error": str(exc),
                        },
                    )
                    await redis.xack(stream, streams.GROUP_DETECTION, stream_id)


if __name__ == "__main__":
    asyncio.run(main())
