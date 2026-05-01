"""Redis Stream naming helpers."""
from __future__ import annotations


def _ns(tenant_id: str) -> str:
    return f"tenant:{tenant_id}"


def events_raw(tenant_id: str) -> str:
    return f"{_ns(tenant_id)}:stream:events:raw"


def events_deadletter(tenant_id: str) -> str:
    return f"{_ns(tenant_id)}:stream:events:deadletter"


def events_failed(tenant_id: str) -> str:
    return f"{_ns(tenant_id)}:stream:events:failed"


def signals_matched(tenant_id: str) -> str:
    return f"{_ns(tenant_id)}:stream:signals:matched"


def signals_enriched(tenant_id: str) -> str:
    return f"{_ns(tenant_id)}:stream:signals:enriched"


def incidents_new(tenant_id: str) -> str:
    return f"{_ns(tenant_id)}:stream:incidents:new"


GROUP_DETECTION = "detection-workers"
GROUP_ENRICHMENT = "enrichment-workers"
GROUP_CORRELATION = "correlation-workers"
GROUP_LLM = "llm-workers"
GROUP_DISPATCHER = "dispatcher-workers"
