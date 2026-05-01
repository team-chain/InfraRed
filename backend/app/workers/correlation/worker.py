"""Correlation worker that creates incidents and triggers role C.

Pipeline stage (B):
    enriched signal (signals:enriched)
        -> track kill-chain stage progression in Redis per (tenant, asset, source_ip)
        -> build Incident (severity / confidence / priority / evidence)
        -> save_or_merge_incident in PostgreSQL
        -> emit trigger onto incidents:new for role C
"""
from __future__ import annotations

import asyncio
from typing import Optional

from prometheus_client import Counter
from redis.asyncio import Redis

from app.common.constants import KillChainStage
from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import save_or_merge_incident
from app.models.incident import CtiEnrichment
from app.models.signal import Signal
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.correlation.builder import build_incident


configure_logging()
log = get_logger(__name__)


CORRELATION_EVENTS = Counter(
    "infrared_correlation_events_total",
    "Outcomes from the correlation worker.",
    ["outcome"],
)


# Higher number = later in the kill chain.
_STAGE_ORDER = {
    KillChainStage.RECONNAISSANCE.value: 1,
    KillChainStage.CREDENTIAL_ACCESS.value: 2,
    KillChainStage.INITIAL_ACCESS.value: 3,
    KillChainStage.EXECUTION.value: 4,
    KillChainStage.PRIVILEGE_ESCALATION.value: 5,
    KillChainStage.DEFENSE_EVASION.value: 6,
    KillChainStage.EXFILTRATION.value: 7,
}
_KILLCHAIN_TTL_SECONDS = 60 * 60  # remember per-IP stage for 1 hour


async def _track_kill_chain(
    redis: Redis,
    signal: Signal,
) -> Optional[str]:
    """Persist the highest kill-chain stage seen for (tenant, asset, ip).

    Returns the *previous* stage if we just advanced, otherwise ``None``. The
    caller can use this to add a transition note to the Evidence Timeline.
    """

    if not signal.source_ip or not signal.kill_chain_stage:
        return None

    key = keys.killchain_stage(
        signal.tenant_id, signal.asset_id, signal.source_ip
    )
    incoming = signal.kill_chain_stage.value
    incoming_rank = _STAGE_ORDER.get(incoming, 0)

    raw = await redis.get(key)
    previous = str(raw) if raw is not None else None
    previous_rank = _STAGE_ORDER.get(previous, 0) if previous else 0

    if incoming_rank > previous_rank:
        await redis.set(key, incoming, ex=_KILLCHAIN_TTL_SECONDS)
        if previous and previous != incoming:
            return previous
    return None


async def process_enriched(signal_payload: str, cti_payload: str) -> tuple[str, bool]:
    settings = get_settings()
    redis = get_redis()
    signal = Signal.model_validate_json(signal_payload)
    cti = CtiEnrichment.model_validate_json(cti_payload)

    advanced_from = await _track_kill_chain(redis, signal)
    incident = build_incident(signal, cti, advanced_from=advanced_from)
    incident_id, created = await save_or_merge_incident(incident)
    if created:
        await redis.xadd(
            streams.incidents_new(incident.tenant_id),
            {
                "incident_id": incident_id,
                "tenant_id": incident.tenant_id,
                "signal_ids": ",".join(incident.signal_ids),
            },
            maxlen=settings.redis_stream_maxlen,
            approximate=True,
        )
        CORRELATION_EVENTS.labels(outcome="incident_created").inc()
    else:
        CORRELATION_EVENTS.labels(outcome="incident_merged").inc()
    return incident_id, created


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
                    incident_id, created = await process_enriched(
                        fields["signal"],
                        fields["cti"],
                    )
                    await redis.xack(stream, streams.GROUP_CORRELATION, stream_id)
                    if created:
                        log.info("incident_created", incident_id=incident_id)
                    else:
                        log.info("incident_merged", incident_id=incident_id)
                except Exception as exc:  # noqa: BLE001
                    CORRELATION_EVENTS.labels(outcome="failed").inc()
                    log.exception("correlation_failed", stream_id=stream_id, error=str(exc))
                    await redis.xack(stream, streams.GROUP_CORRELATION, stream_id)


if __name__ == "__main__":
    asyncio.run(main())
