"""Redis raw-envelope consumer for detection.

Pipeline stage (B):
    raw envelope (events:raw)
        -> dedup (event_id)
        -> parse (auth.log OR nginx, based on raw_source)
        -> persist normalized_event
        -> evaluate rules (AUTH-001..005 for SSH, WEB-001..004 for nginx)
        -> emit Signal(s) onto signals:matched

Failures stay in PEL and are retried via XAUTOCLAIM.  After dlq_max_retries
the message is moved to the dead-letter stream and acknowledged.
"""
from __future__ import annotations

import asyncio

from prometheus_client import Counter

from app.common.constants import EventType
from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import save_normalized_event, save_signal
from app.models.envelope import RawEventEnvelope
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.detection.nginx_parser import parse_nginx_log
from app.workers.detection.parser import parse_auth_log
from app.workers.detection.rules import evaluate_rules
from app.workers.detection.web_rules import evaluate_web_rules
from app.workers.dlq import reclaim_pending


configure_logging()
log = get_logger(__name__)


DETECTION_EVENTS = Counter(
    "infrared_detection_events_total",
    "Detection worker outcomes per raw envelope.",
    ["outcome"],
)
DETECTION_SIGNALS = Counter(
    "infrared_detection_signals_total",
    "Signals emitted by the detection worker.",
    ["rule_id"],
)


def _is_nginx_source(envelope: RawEventEnvelope) -> bool:
    """Return True when the raw envelope originated from an nginx access.log."""
    source = (envelope.raw_source or "").lower()
    return source in {"nginx", "nginx_access", "nginx_access_log"}


async def process_payload(stream_id: str, payload: str) -> None:
    settings = get_settings()
    redis = get_redis()
    envelope = RawEventEnvelope.model_validate_json(payload)

    # ── Event-level dedup ─────────────────────────────────────────────────────
    dedup_key = keys.event_dedup(envelope.tenant_id, envelope.event_id)
    is_new = await redis.set(dedup_key, "1", nx=True, ex=settings.dedup_ttl_seconds)
    if not is_new:
        log.info("event_duplicate_skipped", event_id=envelope.event_id)
        DETECTION_EVENTS.labels(outcome="duplicate").inc()
        return

    # ── Parse: route by raw_source ────────────────────────────────────────────
    if _is_nginx_source(envelope):
        event = parse_nginx_log(envelope)
    else:
        event = parse_auth_log(envelope)

    if event is None:
        log.info("event_unparsed", event_id=envelope.event_id)
        DETECTION_EVENTS.labels(outcome="unparsed").inc()
        return

    await save_normalized_event(event)
    if event.late_event:
        log.info(
            "event_late_processed",
            event_id=event.event_id,
            timestamp=event.timestamp.isoformat(),
        )
        DETECTION_EVENTS.labels(outcome="late_processed").inc()
    else:
        DETECTION_EVENTS.labels(outcome="parsed").inc()

    # ── Evaluate rules: SSH vs Web ────────────────────────────────────────────
    if event.event_type == EventType.WEB_REQUEST:
        signals = await evaluate_web_rules(redis, event)
    else:
        signals = await evaluate_rules(redis, event)

    for signal in signals:
        await save_signal(signal)
        await redis.xadd(
            streams.signals_matched(signal.tenant_id),
            {"payload": signal.model_dump_json()},
            maxlen=settings.redis_stream_maxlen,
            approximate=True,
        )
        DETECTION_SIGNALS.labels(rule_id=signal.rule_id.value).inc()
        log.info("signal_matched", signal_id=signal.signal_id, rule_id=signal.rule_id.value)


async def _handle(stream_id: str, fields: dict) -> None:
    await process_payload(stream_id, fields["payload"])


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    stream = streams.events_raw(settings.tenant_id)
    await ensure_group(redis, stream, streams.GROUP_DETECTION)
    consumer = f"detection-{settings.agent_id}"
    log.info("detection_worker_started", stream=stream, group=streams.GROUP_DETECTION)

    while True:
        # ── Process new messages ──────────────────────────────────────────────
        messages = await redis.xreadgroup(
            streams.GROUP_DETECTION,
            consumer,
            {stream: ">"},
            count=10,
            block=5000,
        )
        if messages:
            for _, entries in messages:
                for stream_id, fields in entries:
                    try:
                        await process_payload(stream_id, fields["payload"])
                        await redis.xack(stream, streams.GROUP_DETECTION, stream_id)
                        DETECTION_EVENTS.labels(outcome="acked").inc()
                    except Exception as exc:  # noqa: BLE001
                        # Leave in PEL for retry via XAUTOCLAIM
                        log.exception("detection_failed", stream_id=stream_id, error=str(exc))
                        DETECTION_EVENTS.labels(outcome="failed").inc()

        # ── Reclaim & retry idle PEL messages (DLQ after max_retries) ────────
        await reclaim_pending(
            redis=redis,
            stream=stream,
            group=streams.GROUP_DETECTION,
            consumer=consumer,
            tenant_id=settings.tenant_id,
            stage="detection",
            idle_ms=settings.dlq_idle_seconds * 1000,
            max_retries=settings.dlq_max_retries,
            handler=_handle,
        )


if __name__ == "__main__":
    asyncio.run(main())
