"""Correlation worker -- creates Incidents and triggers role C.

Pipeline stage (B):
  enriched signal (signals:enriched)
    -> kill-chain stage tracking in Redis
    -> escalate_to_incident check
    -> Incident Dedup (Redis SET NX, incident_dedup_ttl_seconds)
    -> build Incident
    -> save_or_merge_incident in PostgreSQL
    -> Discord 1차 즉시 알림 발송 (설계서 4.3)
    -> emit trigger onto incidents:new for role C (LLM Worker가 2차 알림 발송)
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
from app.dispatcher.discord import send_discord_first_alert
from app.dispatcher.service import _get_tenant_dispatch_config
from app.models.incident import CtiEnrichment, Incident
from app.models.signal import Signal
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.correlation.builder import build_incident
from app.workers.dlq import reclaim_pending
from app.workers.llm.playbook import get_first_alert_summary, get_rule_title
from app.ingestion.sse_routes import publish_incident_event


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
    ip = signal.source_ip or "no-ip"
    username = signal.username or "no-user"
    dedup_key = keys.incident_dedup(
        signal.tenant_id, signal.rule_id.value, signal.asset_id, ip, username,
    )
    is_new = await redis.set(dedup_key, "1", nx=True, ex=settings.incident_dedup_ttl_seconds)
    return bool(is_new)


async def process_enriched(signal_payload: str, cti_payload: str) -> tuple:
    settings = get_settings()
    redis = get_redis()
    signal = Signal.model_validate_json(signal_payload)
    cti = CtiEnrichment.model_validate_json(cti_payload)

    advanced_from = await _track_kill_chain(redis, signal)

    if not signal.escalate_to_incident:
        log.info(
            "signal_no_incident_escalation",
            signal_id=signal.signal_id,
            rule_id=signal.rule_id.value,
            notes=signal.notes,
        )
        CORRELATION_EVENTS.labels(outcome="signal_only").inc()
        return None, False

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

    # Discord 1차 즉시 알림 (설계서 4.3)
    if created and incident.severity.lower() in ("critical", "high", "medium"):
        try:
            tenant_cfg = await _get_tenant_dispatch_config(incident.tenant_id)
            discord_url = tenant_cfg.get("discord_webhook_url") or None
            playbook_summary = get_first_alert_summary(
                rule_id=signal.rule_id.value,
                severity=incident.severity,
                source_ip=signal.source_ip,
                username=signal.username,
            )
            await send_discord_first_alert(
                incident_id=incident_id,
                tenant_id=incident.tenant_id,
                severity=incident.severity,
                rule_id=signal.rule_id.value,
                rule_description=get_rule_title(signal.rule_id.value),
                asset_name=getattr(signal, "asset_id", "") or "",
                source_ip=signal.source_ip,
                playbook_summary=playbook_summary,
                webhook_url=discord_url,
            )
            log.info("discord_first_alert_sent", incident_id=incident_id, severity=incident.severity)
        except Exception as exc:
            log.warning("discord_first_alert_failed", incident_id=incident_id, error=str(exc))

    # SSE Push
    try:
        await publish_incident_event(
            tenant_id=incident.tenant_id,
            event_type="incident_created" if created else "incident_updated",
            data={
                "incident_id": incident_id,
                "severity": incident.severity,
                "kill_chain_stage": incident.kill_chain_stage,
                "source_ip": signal.source_ip,
                "rule_id": signal.rule_id.value,
                "created_at": incident.created_at.isoformat() if hasattr(incident, "created_at") and incident.created_at else None,
            },
        )
    except Exception as exc:
        log.warning("sse_publish_failed", incident_id=incident_id, error=str(exc))

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
                    except Exception as exc:
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
