"""Redis raw-envelope consumer for detection.

Pipeline stage (B):
    raw envelope (events:raw)
        -> dedup (event_id)
        -> parse (auth.log OR nginx, based on raw_source)
        -> persist normalized_event
        -> evaluate rules (AUTH-001..007 for SSH, WEB-001..007 + WEB-HNY-001 for nginx)
        -> Demo Signal  -> demo_signals DB + SSE Pub/Sub (설계서 17.3)
        -> Threat Signal -> signals:matched stream (기존 파이프라인)

Failures stay in PEL and are retried via XAUTOCLAIM.  After dlq_max_retries
the message is moved to the dead-letter stream and acknowledged.
"""
from __future__ import annotations

import asyncio
import hashlib
import json

from prometheus_client import Counter

from app.common.constants import EventType, SignalCategory
from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import save_demo_signal, save_normalized_event, save_signal
from app.models.demo_signal import DemoSignal
from app.models.envelope import RawEventEnvelope
from app.models.signal import Signal as _Signal
from app.redis_kv import keys, streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.detection.agent_event_rules import evaluate_agent_event, is_agent_event
from app.workers.detection.nginx_parser import parse_nginx_log
from app.workers.detection.parser import parse_auth_log
from app.workers.detection.rules import evaluate_rules
from app.workers.detection.web_rules import evaluate_net_rules, evaluate_web_rules
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


def _mask_ip(ip: str | None) -> str | None:
    """마지막 두 옥텟을 xx로 마스킹 (예: 121.135.10.20 -> 121.135.xx.xx)."""
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.xx.xx"
    return ip  # IPv6 등은 그대로


def _hash_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    return hashlib.sha256(ip.encode()).hexdigest()


async def _handle_demo_signal(signal: _Signal, envelope: RawEventEnvelope) -> None:
    """Demo Signal -> demo_signals DB 저장 + SSE Redis Pub/Sub 발행 (설계서 17.3)."""
    from app.common.constants import HONEYPOT_PATH_SEVERITY
    from app.redis_kv.client import get_redis as _get_redis

    redis = _get_redis()
    ip_hash = _hash_ip(signal.source_ip)

    # Honeypot 방문 dedup (24h, 동일 IP 중복 카드 방지)
    if ip_hash:
        dedup_key = keys.honeypot_visit(signal.tenant_id, ip_hash)
        await redis.set(dedup_key, "1", nx=True, ex=86400)

    # notes에서 경로 추출 (evaluate_honeypot이 "Honeypot path accessed: /path (severity=...)" 형식으로 기록)
    path = "/demo"
    if signal.notes and "Honeypot path accessed:" in signal.notes:
        try:
            path = signal.notes.split("Honeypot path accessed:")[1].split("(")[0].strip()
        except Exception:
            pass
    path = path.split("?")[0].rstrip("/") or "/demo"
    severity = HONEYPOT_PATH_SEVERITY.get(path, "info")

    demo = DemoSignal(
        demo_signal_id=signal.signal_id.replace("SIG-", "DEMO-"),
        tenant_id=signal.tenant_id,
        asset_id=signal.asset_id,
        source_ip_masked=_mask_ip(signal.source_ip),
        source_ip_hash=ip_hash,
        path=path,
        severity=severity,
        detected_at=signal.detected_at,
    )
    await save_demo_signal(demo)

    # SSE push용 Redis Pub/Sub 발행 (Person B의 SSE 엔드포인트가 구독)
    await redis.publish(
        f"tenant:{signal.tenant_id}:sse",
        json.dumps({
            "event": "demo_visitor",
            "data": {
                "demo_signal_id": demo.demo_signal_id,
                "source_ip_masked": demo.source_ip_masked,
                "path": demo.path,
                "severity": demo.severity,
                "detected_at": demo.detected_at.isoformat(),
            },
        }),
    )
    log.info("demo_signal_saved", demo_signal_id=demo.demo_signal_id, path=demo.path)


def _is_nginx_source(envelope: RawEventEnvelope) -> bool:
    """Return True when the raw envelope originated from an nginx access.log."""
    if envelope.event_type == EventType.WEB_REQUEST:
        return True
    source = (envelope.raw_source or "").lower()
    return source in {"nginx", "nginx_access", "nginx_access_log", "sdk", "web"}


async def process_payload(stream_id: str, payload: str) -> None:
    settings = get_settings()
    redis = get_redis()
    envelope = RawEventEnvelope.model_validate_json(payload)

    # -- Event-level dedup -----------------------------------------------------
    dedup_key = keys.event_dedup(envelope.tenant_id, envelope.event_id)
    is_new = await redis.set(dedup_key, "1", nx=True, ex=settings.dedup_ttl_seconds)
    if not is_new:
        log.info("event_duplicate_skipped", event_id=envelope.event_id)
        DETECTION_EVENTS.labels(outcome="duplicate").inc()
        return

    # -- Parse: route by raw_source --------------------------------------------
    # Agent 사전 분류 이벤트 (FIM/EXEC)는 별도 처리 — 룰 매칭 없이 즉시 Signal로
    if is_agent_event(envelope):
        signals = await evaluate_agent_event(envelope)
        DETECTION_EVENTS.labels(outcome="agent_event").inc()
        log.info(
            "agent_event_processed",
            event_id=envelope.event_id,
            rule_id=envelope.model_dump().get("rule_id"),
            raw_source=envelope.raw_source,
            signal_count=len(signals),
        )
        # NOTE: agent 이벤트는 NormalizedEvent 변환 없이 바로 signals dispatch
        # save_normalized_event는 SSH/web 이벤트 전용 (event_type enum 제약)
    else:
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

        # -- Evaluate rules: SSH vs Web (+ NET-001 HTTP Flood) ----------------
        if event.event_type == EventType.WEB_REQUEST:
            signals = await evaluate_web_rules(redis, event)
            # NET-001: WEB_REQUEST 이벤트에서 HTTP Flood 추가 평가 (설계서 3.1)
            net_signals = await evaluate_net_rules(redis, event)
            signals.extend(net_signals)
        else:
            signals = await evaluate_rules(redis, event)

    for signal in signals:
        # -- Demo Signal 분기 (설계서 17.3) ------------------------------------
        # is_demo=True인 Signal은 demo_signals에 저장하고 파이프라인에 진입하지 않음
        if getattr(signal, "is_demo", False) or getattr(signal, "category", None) == SignalCategory.DEMO:
            try:
                await _handle_demo_signal(signal, envelope)
            except Exception as exc:
                log.warning("demo_signal_failed", signal_id=signal.signal_id, error=str(exc))
            continue

        # -- Threat Signal -> 기존 파이프라인 -----------------------------------
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
        # -- Process new messages ----------------------------------------------
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

        # -- Reclaim & retry idle PEL messages (DLQ after max_retries) ---------
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
