"""Prometheus 호환 /metrics 엔드포인트.

prometheus_client 사용:
  - Counter:   incidents_total, signals_total, llm_calls_total, api_requests_total
  - Gauge:     agents_online_gauge, open_incidents_gauge, redis_queue_depth_gauge
  - Histogram: response_time_histogram, llm_latency_histogram

FastAPI 미들웨어 + GET /metrics 엔드포인트 포함.
"""
from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
    REGISTRY,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

log = logging.getLogger(__name__)

metrics_router = APIRouter(tags=["observability"])


# ────────────────────────────────────────────────────────────────────────────
# 메트릭 정의 (싱글턴 — 중복 등록 방지)
# ────────────────────────────────────────────────────────────────────────────

def _get_or_create(metric_class, name: str, documentation: str, labelnames=(), **kwargs):
    """이미 등록된 메트릭이 있으면 재사용, 없으면 생성."""
    try:
        return metric_class(name, documentation, labelnames=labelnames, **kwargs)
    except ValueError:
        # 이미 등록됨 — 기존 메트릭 반환
        return REGISTRY._names_to_collectors.get(name)  # type: ignore[attr-defined]


# Counters
INCIDENTS_TOTAL = _get_or_create(
    Counter,
    "infrared_incidents_total",
    "Total incidents created, labeled by severity and disposition.",
    labelnames=["severity", "disposition", "tenant_id"],
)

SIGNALS_TOTAL = _get_or_create(
    Counter,
    "infrared_signals_total",
    "Total threat signals detected, labeled by rule_id.",
    labelnames=["rule_id", "tenant_id"],
)

LLM_CALLS_TOTAL = _get_or_create(
    Counter,
    "infrared_llm_calls_total",
    "Total LLM API calls, labeled by provider and outcome.",
    labelnames=["provider", "outcome"],
)

API_REQUESTS_TOTAL = _get_or_create(
    Counter,
    "infrared_api_requests_total",
    "Total HTTP requests processed.",
    labelnames=["method", "path", "status_code"],
)

DETECTION_EVENTS_TOTAL = _get_or_create(
    Counter,
    "infrared_detection_events_total",
    "Detection worker events processed by outcome.",
    labelnames=["outcome"],
)

BLOCK_ACTIONS_TOTAL = _get_or_create(
    Counter,
    "infrared_block_actions_total",
    "Automated block actions executed.",
    labelnames=["action_type", "tenant_id"],
)

# Gauges
AGENTS_ONLINE_GAUGE = _get_or_create(
    Gauge,
    "infrared_agents_online",
    "Number of agents currently online (heartbeat within 5 min).",
    labelnames=["tenant_id"],
)

OPEN_INCIDENTS_GAUGE = _get_or_create(
    Gauge,
    "infrared_open_incidents",
    "Number of currently open incidents.",
    labelnames=["severity", "tenant_id"],
)

REDIS_QUEUE_DEPTH_GAUGE = _get_or_create(
    Gauge,
    "infrared_redis_queue_depth",
    "Redis stream pending message count.",
    labelnames=["stream", "group"],
)

DENYLIST_SIZE_GAUGE = _get_or_create(
    Gauge,
    "infrared_denylist_size",
    "Number of IPs in the active denylist.",
    labelnames=["tenant_id"],
)

LLM_CACHE_HIT_GAUGE = _get_or_create(
    Gauge,
    "infrared_llm_cache_hit_ratio",
    "LLM response cache hit ratio (0.0–1.0).",
    labelnames=[],
)

# Histograms
RESPONSE_TIME_HISTOGRAM = _get_or_create(
    Histogram,
    "infrared_http_response_duration_seconds",
    "HTTP request latency.",
    labelnames=["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

LLM_LATENCY_HISTOGRAM = _get_or_create(
    Histogram,
    "infrared_llm_latency_seconds",
    "LLM API call latency.",
    labelnames=["provider"],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0),
)

SIGNAL_PROCESSING_HISTOGRAM = _get_or_create(
    Histogram,
    "infrared_signal_processing_seconds",
    "Time to process a signal through the detection pipeline.",
    labelnames=["rule_id"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)


# ────────────────────────────────────────────────────────────────────────────
# 헬퍼: 메트릭 기록 함수
# ────────────────────────────────────────────────────────────────────────────

def record_incident(severity: str, disposition: str, tenant_id: str) -> None:
    """인시던트 생성 시 호출."""
    if INCIDENTS_TOTAL:
        INCIDENTS_TOTAL.labels(
            severity=severity,
            disposition=disposition or "unknown",
            tenant_id=tenant_id,
        ).inc()


def record_signal(rule_id: str, tenant_id: str) -> None:
    """시그널 탐지 시 호출."""
    if SIGNALS_TOTAL:
        SIGNALS_TOTAL.labels(rule_id=rule_id, tenant_id=tenant_id).inc()


def record_llm_call(provider: str, outcome: str, latency_seconds: float) -> None:
    """LLM 호출 후 호출."""
    if LLM_CALLS_TOTAL:
        LLM_CALLS_TOTAL.labels(provider=provider, outcome=outcome).inc()
    if LLM_LATENCY_HISTOGRAM:
        LLM_LATENCY_HISTOGRAM.labels(provider=provider).observe(latency_seconds)


def record_block_action(action_type: str, tenant_id: str) -> None:
    """자동 차단 실행 시 호출."""
    if BLOCK_ACTIONS_TOTAL:
        BLOCK_ACTIONS_TOTAL.labels(action_type=action_type, tenant_id=tenant_id).inc()


# ────────────────────────────────────────────────────────────────────────────
# 동적 게이지 수집 (DB/Redis 쿼리 기반)
# ────────────────────────────────────────────────────────────────────────────

async def refresh_gauges(app_state) -> None:
    """백그라운드 태스크: 주기적으로 게이지 값을 DB/Redis 에서 갱신."""
    try:
        db_pool = getattr(app_state, "db_pool", None)
        redis = getattr(app_state, "redis", None)

        if db_pool:
            async with db_pool.acquire() as conn:
                # 온라인 에이전트 수
                agents = await conn.fetch(
                    """
                    SELECT tenant_id, COUNT(*) AS cnt
                    FROM agents
                    WHERE last_heartbeat_at > NOW() - INTERVAL '5 minutes'
                      AND status = 'online'
                    GROUP BY tenant_id
                    """
                )
                for row in agents:
                    AGENTS_ONLINE_GAUGE.labels(tenant_id=row["tenant_id"]).set(row["cnt"])

                # 오픈 인시던트
                open_inc = await conn.fetch(
                    """
                    SELECT tenant_id, severity, COUNT(*) AS cnt
                    FROM incidents
                    WHERE status IN ('open', 'in_progress')
                    GROUP BY tenant_id, severity
                    """
                )
                for row in open_inc:
                    OPEN_INCIDENTS_GAUGE.labels(
                        severity=row["severity"], tenant_id=row["tenant_id"]
                    ).set(row["cnt"])

                # Denylist 크기
                deny_sizes = await conn.fetch(
                    """
                    SELECT tenant_id, COUNT(*) AS cnt
                    FROM ip_denylist
                    WHERE (expires_at IS NULL OR expires_at > NOW())
                    GROUP BY tenant_id
                    """
                )
                for row in deny_sizes:
                    DENYLIST_SIZE_GAUGE.labels(tenant_id=row["tenant_id"]).set(row["cnt"])

        if redis:
            # Redis 스트림 pending 깊이
            for stream_key in ["events:raw", "signals:matched", "signals:enriched"]:
                try:
                    info = await redis.xinfo_groups(stream_key)
                    for group in info:
                        REDIS_QUEUE_DEPTH_GAUGE.labels(
                            stream=stream_key,
                            group=group.get("name", "unknown"),
                        ).set(int(group.get("pending", 0)))
                except Exception:
                    pass  # 스트림이 없으면 무시

    except Exception as exc:
        log.warning("refresh_gauges_failed error=%s", exc)


# ────────────────────────────────────────────────────────────────────────────
# FastAPI 미들웨어: 요청 레이턴시 자동 기록
# ────────────────────────────────────────────────────────────────────────────

async def prometheus_middleware(request: Request, call_next: Callable) -> Response:
    """모든 HTTP 요청의 레이턴시와 상태 코드를 기록."""
    start = time.perf_counter()
    # 경로 정규화 (path param 제거)
    path = request.url.path
    # /api/v1/incidents/{id} → /api/v1/incidents/{id}  (그대로)
    # 단, UUID/숫자 파라미터는 {param} 으로 치환
    import re
    normalized_path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{uuid}",
        path,
    )
    normalized_path = re.sub(r"/\d+", "/{id}", normalized_path)

    try:
        response = await call_next(request)
        duration = time.perf_counter() - start

        if RESPONSE_TIME_HISTOGRAM:
            RESPONSE_TIME_HISTOGRAM.labels(
                method=request.method, path=normalized_path
            ).observe(duration)

        if API_REQUESTS_TOTAL:
            API_REQUESTS_TOTAL.labels(
                method=request.method,
                path=normalized_path,
                status_code=str(response.status_code),
            ).inc()

        return response
    except Exception as exc:
        duration = time.perf_counter() - start
        if API_REQUESTS_TOTAL:
            API_REQUESTS_TOTAL.labels(
                method=request.method,
                path=normalized_path,
                status_code="500",
            ).inc()
        raise


# ────────────────────────────────────────────────────────────────────────────
# FastAPI 엔드포인트
# ────────────────────────────────────────────────────────────────────────────

@metrics_router.get(
    "/metrics",
    response_class=PlainTextResponse,
    summary="Prometheus 메트릭 스크래핑 엔드포인트",
    include_in_schema=False,
)
async def get_metrics(request: Request):
    """
    Prometheus 가 스크래핑하는 /metrics 엔드포인트.
    PROMETHEUS_BEARER_TOKEN 설정 시 Bearer 인증 필요.
    """
    settings = request.app.state.settings
    bearer_token: str = getattr(settings, "prometheus_bearer_token", "")

    if bearer_token:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer ") or auth_header[7:] != bearer_token:
            raise HTTPException(status_code=401, detail="Unauthorized")

    # 게이지 갱신 (비동기, 실패 시 이전 값 사용)
    try:
        await refresh_gauges(request.app.state)
    except Exception:
        pass

    output = generate_latest(REGISTRY)
    return Response(content=output, media_type=CONTENT_TYPE_LATEST)


@metrics_router.get("/metrics/summary", summary="메트릭 요약 (JSON)")
async def get_metrics_summary(request: Request):
    """주요 메트릭의 현재 값을 JSON 으로 반환 (관리자용)."""
    await refresh_gauges(request.app.state)

    samples: dict = {}
    for metric in REGISTRY.collect():
        if metric.name.startswith("infrared_"):
            metric_data = {}
            for sample in metric.samples:
                label_str = "_".join(f"{k}_{v}" for k, v in sample.labels.items()) if sample.labels else "total"
                metric_data[label_str] = sample.value
            samples[metric.name] = metric_data

    return {"metrics": samples, "timestamp": time.time()}
