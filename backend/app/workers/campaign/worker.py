"""Campaign Aggregation Worker (v3.0 신규).

동일 source_ip가 여러 자산(asset)을 대상으로 단기간에 다수의 시그널을
생성하는 경우 '캠페인(Campaign)'으로 탐지하여 알림을 발송한다.

알고리즘:
  signals:enriched 스트림에서 시그널을 읽어
    Redis Sorted Set  tenant:{tid}:campaign:ip:{ip}
      member = asset_id, score = timestamp(unix)
  를 유지하면서 윈도우 내 신호 수 / 대상 자산 수가 임계치를 초과하면
  캠페인으로 탐지 → 로그 출력 + Discord/Slack 웹훅 전송(설정된 경우)

설정(env):
  CAMPAIGN_WINDOW_SECONDS   = 600   (기본 10분)
  CAMPAIGN_MIN_SIGNALS      = 5     (윈도우 내 최소 시그널 수)
  CAMPAIGN_MIN_TARGETS      = 2     (최소 피해 자산 수)
"""
from __future__ import annotations

import asyncio
import json
import time

import httpx
from redis.asyncio import Redis

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.models.signal import Signal
from app.redis_kv import streams
from app.redis_kv.client import ensure_group, get_redis
from app.workers.dlq import reclaim_pending


configure_logging()
log = get_logger(__name__)

# Redis key prefix for campaign tracking sorted sets
def _campaign_key(tenant_id: str, source_ip: str) -> str:
    return f"tenant:{tenant_id}:campaign:ip:{source_ip}"

# Redis key for campaign dedup (avoid repeated alerts for same IP within window)
def _campaign_alert_dedup(tenant_id: str, source_ip: str) -> str:
    return f"tenant:{tenant_id}:campaign:alerted:{source_ip}"


async def _send_webhook(url: str, payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json=payload)
    except Exception as exc:
        log.warning("campaign_webhook_failed", error=str(exc))


async def _notify_campaign(
    tenant_id: str,
    source_ip: str,
    signal_count: int,
    target_assets: list[str],
    settings,
) -> None:
    message = (
        f"🚨 **캠페인 탐지** | IP: `{source_ip}` → "
        f"{signal_count}개 시그널, {len(target_assets)}개 자산 타깃 "
        f"[{', '.join(target_assets[:5])}{'...' if len(target_assets) > 5 else ''}]"
    )
    log.warning(
        "campaign_detected",
        tenant_id=tenant_id,
        source_ip=source_ip,
        signal_count=signal_count,
        target_count=len(target_assets),
        targets=target_assets[:10],
    )

    # Discord 알림
    if settings.discord_webhook_url:
        await _send_webhook(
            settings.discord_webhook_url,
            {"content": message},
        )

    # Slack 알림
    slack_url = getattr(settings, "slack_webhook_url", "")
    if slack_url:
        await _send_webhook(
            slack_url,
            {"text": message},
        )


async def process_signal(redis: Redis, signal: Signal, settings) -> None:
    """시그널 하나를 처리해 캠페인 집계 상태를 갱신한다."""
    if not signal.source_ip:
        return

    source_ip = str(signal.source_ip)
    now = time.time()
    window_start = now - settings.campaign_window_seconds

    key = _campaign_key(signal.tenant_id, source_ip)

    # 1) 현재 asset_id 를 현재 타임스탬프로 추가 (ZADD)
    await redis.zadd(key, {signal.asset_id: now})
    # 윈도우 만료 설정 (window * 2 여유)
    await redis.expire(key, settings.campaign_window_seconds * 2)

    # 2) 오래된 항목 제거 (윈도우 밖)
    await redis.zremrangebyscore(key, "-inf", window_start)

    # 3) 윈도우 내 고유 자산 수 및 총 멤버(시그널 대리) 확인
    members = await redis.zrangebyscore(key, window_start, "+inf", withscores=False)
    # members 에는 asset_id 값들이 중복 포함될 수 있으므로 유니크 카운트
    unique_assets = set(m.decode() if isinstance(m, bytes) else m for m in members)
    total_in_window = len(members)  # 중복 포함 횟수 → 시그널 수 근사치

    if (
        total_in_window >= settings.campaign_min_signals
        and len(unique_assets) >= settings.campaign_min_targets
    ):
        # 4) 중복 알림 방지 (윈도우 내 1회만)
        dedup_key = _campaign_alert_dedup(signal.tenant_id, source_ip)
        is_new = await redis.set(
            dedup_key, "1", nx=True, ex=settings.campaign_window_seconds
        )
        if is_new:
            await _notify_campaign(
                tenant_id=signal.tenant_id,
                source_ip=source_ip,
                signal_count=total_in_window,
                target_assets=sorted(unique_assets),
                settings=settings,
            )


async def _handle(stream_id: str, fields: dict) -> None:
    settings = get_settings()
    redis = get_redis()
    try:
        signal = Signal.model_validate_json(fields["signal"])
        await process_signal(redis, signal, settings)
    except Exception as exc:
        log.exception("campaign_handle_failed", stream_id=stream_id, error=str(exc))


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    stream = streams.signals_enriched(settings.tenant_id)
    await ensure_group(redis, stream, streams.GROUP_CAMPAIGN)
    consumer = f"campaign-{settings.agent_id}"
    log.info(
        "campaign_worker_started",
        stream=stream,
        window_sec=settings.campaign_window_seconds,
        min_signals=settings.campaign_min_signals,
        min_targets=settings.campaign_min_targets,
    )

    while True:
        try:
            messages = await redis.xreadgroup(
                streams.GROUP_CAMPAIGN,
                consumer,
                {stream: ">"},
                count=50,
                block=5000,
            )
            if messages:
                for _, entries in messages:
                    for stream_id, fields in entries:
                        try:
                            await _handle(stream_id, fields)
                            await redis.xack(stream, streams.GROUP_CAMPAIGN, stream_id)
                        except Exception as exc:
                            log.exception(
                                "campaign_entry_failed",
                                stream_id=stream_id,
                                error=str(exc),
                            )

            await reclaim_pending(
                redis=redis,
                stream=stream,
                group=streams.GROUP_CAMPAIGN,
                consumer=consumer,
                tenant_id=settings.tenant_id,
                stage="campaign",
                idle_ms=settings.dlq_idle_seconds * 1000,
                max_retries=settings.dlq_max_retries,
                handler=_handle,
            )
        except Exception as exc:
            log.exception("campaign_worker_loop_error", error=str(exc))
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
