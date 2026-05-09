"""Correlation worker — creates Incidents and triggers role C.

Pipeline stage (B):
  enriched signal (signals:enriched)
    -> kill-chain stage tracking in Redis
    -> escalate_to_incident check  (AUTH-004 design doc 6.2 — skip if False)
    -> Incident Dedup (Redis SET NX, incident_dedup_ttl_seconds)
    -> build Incident
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
from app.workers.dlq import reclaim_pending


configure_logging()
log = get_logger(__name__)

CORRELATION_EVENTS = Counter(
    "infrared_correlation_events_total",
    "Outcomes from the correlation worker.",
    ["outcome"],
)

_STAGE_ORDER = {
    KillChainStage.RECONNAISSANCE.value: 1,
    KillChainStage.CREDENTIAL_ACCESS.value: 2,
    KillChainStage.INITIAL_ACCESS.value: 3,
    KillChainStage.EXECUTION.value: 4,
    KillChainStage.PRIVILEGE_ESCALATION.value: 5,
    KillChainStage.DEFENSE_EVASION.value: 6,
    KillChainStage.EXFILTRATION.value: 7,
}
_KILLCHAIN_TTL_SECONDS = 60 * 60


async def _track_kill_chain(redis: Redis, signal: Signal) -> Optional[str]:
    """Track kill-chain stage per (tenant, asset, ip). Returns previous stage if advanced."""
    if not signal.source_ip or not signal.kill_chain_stage:
        return None
    key = keys.killchain_stage(signal.tenant_id, signal.asset_id, signal.source_ip)
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


async def _check_incident_dedup(redis: Redis, signal: Signal, settings) -> bool:
    """Redis SET NX dedup check (design doc section 4, 10-min TTL).
    Returns True if new (not duplicate), False if duplicate.
    """
    ip = signal.source_ip or "no-ip"
    username = signal.username or "no-user"
    dedup_key = keys.incident_dedup(
        signal.tenant_id, signal.rule_id.value, signal.asset_id, ip, username,
    )
    is_new = await redis.set(dedup_key, "1", nx=True, ex=settings.incident_dedup_ttl_seconds)
    return bool(is_new)


async def process_enriched(signal_payload: str, cti_payload: str) -> tuple:
    """Process one enriched signal. Returns (incident_id, created) or (None, False) if skipped."""
    settings = get_settings()
    redis = get_redis()
    signal = Signal.model_validate_json(signal_payload)
    cti = CtiEnrichment.model_validate_json(cti_payload)

    # Kill-chain tracking always runs regardless of escalation
    advanced_from = await _track_kill_chain(redis, signal)

    # Gate 1: escalate_to_incident (AUTH-004 design doc 6.2)
    if not signal.escalate_to_incident:
        log.info(
            "signal_no_incident_escalation",
            signal_id=signal.signal_id,
            rule_id=signal.rule_id.value,
            notes=signal.notes,
        )
        CORRELATION_EVENTS.labels(outcome="signal_only").inc()
        return None, False

    # Gate 2: Incident Dedup (Redis SET NX, 10-min TTL)
    is_new_dedup = await _check_incident_dedup(redis, signal, settings)
    if not is_new_dedup:
        log.info(
            "incident_dedup_skipped",
            signal_id=signal.signal_id,
            rule_id=signal.rule_id.value,
            source_ip=signal.source_ip,
            username=signal.username,
        )
        CORRELATION_EVENTS.labels(outcome="dedup_skipped").inc()
        return None, False

    incident = build_incident(signal, cti, advanced_from=advanced_from)
    incident_id, created = await save_or_merge_incident(incident)
    await redis.xadd(
        streams.incidents_new(incident.tenant_id),
        {
            "incident_id": incident_id,
            "tenant_id": incident.tenant_id,
            "signal_ids": ",".join(incident.signal_ids),
            "event_type": "incident_created" if created else "incident_updated",
            "refresh": "false" if created else "true",
        },
        maxlen=settings.redis_stream_maxlen,
        approximate=True,
    )
    if created:
        CORRELATION_EVENTS.labels(outcome="incident_created").inc()
    else:
        CORRELATION_EVENTS.labels(outcome="incident_merged").inc()
    return incident_id, created


async def _handle(stream_id: str, fields: dict) -> None:
    incident_id, created = await process_enriched(fields["signal"], fields["cti"])
    if incident_id and created:
        log.info("incident_created", incident_id=incident_id)
    elif incident_id:
        log.info("incident_merged", incident_id=incident_id)


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
        if messages:
            for _, entries in messages:
                for stream_id, fields in entries:
                    try:
                        incident_id, created = await process_enriched(
                            fields["signal"], fields["cti"],
                        )
                        await redis.xack(stream, streams.GROUP_CORRELATION, stream_id)
                        if incident_id and created:
                            CORRELATION_EVENTS.labels(outcome="incident_created").inc()
                        elif incident_id:
                            CORRELATION_EVENTS.labels(outcome="incident_merged").inc()
                    except Exception as exc:  # noqa: BLE001
                        CORRELATION_EVENTS.labels(outcome="failed").inc()
                        log.exception("correlation_failed", stream_id=stream_id, error=str(exc))

        await reclaim_pending(
            redis=redis,
            stream=stream,
            group=streams.GROUP_CORRELATION,
            consumer=consumer,
            tenant_id=settings.tenant_id,
            stage="correlation",
            idle_ms=settings.dlq_idle_seconds * 1000,
            max_retries=settings.dlq_max_retries,
            handler=_handle,
        )


if __name__ == "__main__":
    asyncio.run(main())
